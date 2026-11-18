// Hoopty backend — Node + Express + Stripe.
// Collect at booking. Hoopty takes its cut, host gets paid via Stripe Connect.
//
// WHO PAYS THE STRIPE FEE (Kris, Nov 17, 2026): the HOST pays it out of
// their share. Hoopty keeps its FULL cut (30/20/10%). The renter pays the
// trip total only — no fee added on top. See backend/lib/fees.js and
// ARCHITECTURE.md ("Host pays the Stripe fee") for the full reasoning.
//
// WHAT IT DOES
//   1. Serves listings (replaces the broken ./_viewer fetch on GitHub Pages).
//   2. Stripe Identity: creates a VerificationSession so a renter can verify
//      their driver's license + selfie BEFORE their first booking.
//   3. Stripe Checkout: creates a Checkout Session at booking time. Renter
//      pays the trip total to the Hoopty platform account. NO
//      application_fee_amount, NO transfer_data.destination — this is a
//      SEPARATE charge, not a destination charge (see below).
//   4. Webhook: marks bookings paid, then creates the host's Transfer for
//      hostGross - ACTUAL Stripe fee (read from the charge's
//      balance_transaction). That is the step that makes the host bear the
//      fee exactly. Never trust the frontend's word that a payment
//      happened — only the webhook.
//   5. Connect onboarding: creates an Express connected account for a host
//      and returns a Stripe-hosted onboarding link.
//
// WHY SEPARATE CHARGES AND TRANSFERS (not a destination charge):
// With a destination charge the transfer is total - application_fee, and
// Stripe's fee comes out of the PLATFORM balance — so Hoopty would still
// pay the fee unless application_fee were inflated by an ESTIMATED fee.
// The real fee varies by payment method (card brand, international card,
// Klarna, Cash App, …), so an estimate can never make Hoopty whole
// exactly. Separate charges and transfers lets the webhook read the
// ACTUAL fee and transfer hostGross - actualFee, so Hoopty retains exactly
// its full cut whatever the fee was. Limit: the transfer happens after
// payment, in the webhook — if the webhook or transfer fails, the booking
// is paid but transferStatus stays "pending"/"failed" and must be retried
// (see createHostTransfer + POST /api/bookings/:id/retry-transfer).
// Refunds/disputes are NOT handled here: a refunded trip needs its
// transfer reversed by hand in the Dashboard until that is built.
//
// WHAT IT NEVER DOES
//   - Never puts a Stripe secret key in frontend code. The secret key lives
//     only in the STRIPE_SECRET_KEY env var on the server.
//   - Never creates a Checkout Session for a host who hasn't finished
//     Connect onboarding (no destination account = no payout path).
//   - Never lets a renter book before Identity says "verified".
//   - Never leaks a host's Connect account id to the browser.
//
// RUN
//   npm install
//   cp .env.example .env   # fill in the real keys from the Stripe Dashboard
//   npm start              # listens on PORT (default 3000)
//
// KEYS (Stripe Dashboard > Developers > API keys — use a RESTRICTED key):
//   STRIPE_SECRET_KEY      — needs: Checkout Sessions (write), Identity
//     VerificationSessions (write), Accounts + AccountLinks (write),
//     PaymentIntents/Charges (read), Transfers (write — the webhook
//     creates the host's transfer after payment).
//   STRIPE_WEBHOOK_SECRET — from Dashboard > Developers > Webhooks, for the
//     endpoint URL you register (https://<your-host>/api/webhook).

const express = require('express');
const fs = require('fs');
const path = require('path');
const Stripe = require('stripe');
const {
  tripTotalCents,
  splitTrip,
  planFromString,
  actualHostNetCents,
  feeShortfallCents,
  usd,
} = require('./lib/fees');

const PORT = Number(process.env.PORT || 3000);
const FRONTEND_URL = (process.env.FRONTEND_URL || 'https://hoopty.rent').replace(/\/$/, '');
const DATA_DIR = path.join(__dirname, 'data');
const LISTINGS_FILE = path.join(DATA_DIR, 'listings.json');
const BOOKINGS_FILE = path.join(DATA_DIR, 'bookings.json');
const RENTERS_FILE = path.join(DATA_DIR, 'renters.json');
const HOSTS_FILE = path.join(DATA_DIR, 'hosts.json');

const app = express();

// The webhook needs the RAW body for signature verification — register it
// before the JSON parser, on its own path.
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const stripe = getStripe(res);
  if (!stripe) return; // getStripe already replied 503
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).json({ ok: false, error: `Webhook signature failed: ${err.message}` });
  }

  if (event.type === 'checkout.session.completed') {
    const s = event.data.object;
    if (s.payment_status === 'paid') {
      const booking = findBookingByCheckoutSession(s.id);
      if (booking) {
        booking.status = 'paid';
        booking.stripePaymentIntentId = s.payment_intent;
        booking.paidAt = new Date().toISOString();
        saveBookings(loadBookings().map((b) => (b.id === booking.id ? booking : b)));
        // The host's payout is a SEPARATE transfer, created here — after
        // payment, once the ACTUAL Stripe fee is known. See createHostTransfer.
        await createHostTransfer(stripe, booking);
      }
    }
  }

  if (event.type === 'identity.verification_session.verified') {
    const vs = event.data.object;
    const email = (vs.metadata && vs.metadata.renter_email) || '';
    if (email) markRenterVerified(email, vs.id);
  }

  if (event.type === 'identity.verification_session.requires_input') {
    const vs = event.data.object;
    const email = (vs.metadata && vs.metadata.renter_email) || '';
    if (email) markRenterFailed(email, vs.id, (vs.last_error && vs.last_error.reason) || 'requires_input');
  }

  return res.json({ ok: true, received: event.type });
});

app.use(express.json());
app.use((req, res, next) => {
  // GitHub Pages origin + local test pages. Tighten this allow-list at deploy.
  res.setHeader('Access-Control-Allow-Origin', process.env.CORS_ORIGIN || FRONTEND_URL);
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function getStripe(res) {
  if (!process.env.STRIPE_SECRET_KEY) {
    res.status(503).json({
      ok: false,
      error: 'Stripe is not configured on this server (STRIPE_SECRET_KEY missing).',
    });
    return null;
  }
  return Stripe(process.env.STRIPE_SECRET_KEY);
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}
function writeJson(file, data) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
const loadListings = () => readJson(LISTINGS_FILE, []);
const saveListings = (l) => writeJson(LISTINGS_FILE, l);
const loadBookings = () => readJson(BOOKINGS_FILE, []);
const saveBookings = (b) => writeJson(BOOKINGS_FILE, b);
const loadRenters = () => readJson(RENTERS_FILE, {});
const saveRenters = (r) => writeJson(RENTERS_FILE, r);
const loadHosts = () => readJson(HOSTS_FILE, {});
const saveHosts = (h) => writeJson(HOSTS_FILE, h);
const findBookingByCheckoutSession = (id) =>
  loadBookings().find((b) => b.stripeCheckoutSessionId === id);

function markRenterVerified(email, verificationSessionId) {
  const renters = loadRenters();
  renters[email.toLowerCase()] = {
    email: email.toLowerCase(),
    identityStatus: 'verified',
    verificationSessionId,
    verifiedAt: new Date().toISOString(),
  };
  saveRenters(renters);
}
function markRenterFailed(email, verificationSessionId, reason) {
  const renters = loadRenters();
  renters[email.toLowerCase()] = {
    email: email.toLowerCase(),
    identityStatus: 'failed',
    verificationSessionId,
    failureReason: reason,
    updatedAt: new Date().toISOString(),
  };
  saveRenters(renters);
}

// ---------------------------------------------------------------------------
// Host payout — separate charges and transfers (see header comment)
// ---------------------------------------------------------------------------
// Creates the host's Transfer AFTER the charge succeeds, using the ACTUAL
// Stripe fee from the charge's balance_transaction:
//   transfer = hostGross - actualFee;  Hoopty retains total - transfer - fee
//   = its FULL cut, whatever the fee was.
// Idempotent: if the booking already has a transfer id, do nothing.
// On failure the booking stays "paid" but transferStatus is "failed" with
// the error recorded — retry with POST /api/bookings/:id/retry-transfer.
// (That endpoint is an admin operation: protect it with an admin key at
// deploy time; it is not part of the renter/host UI.)
function saveBookingPatch(bookingId, patch) {
  saveBookings(loadBookings().map((b) => (b.id === bookingId ? { ...b, ...patch } : b)));
}

// Small delay helper for the fee-read retry loop below.
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Read the ACTUAL Stripe fee from the charge, retrying while Stripe is
// still settling the payment.
//
// ROOT CAUSE (test booking bk_mwlxhidw, Nov 18, 2026): the webhook fires on
// checkout.session.completed as soon as payment_status is "paid", but at
// that moment the charge's balance_transaction is not always populated
// yet — latest_charge.balance_transaction can come back null, or as a
// bare string id instead of the expanded object, so the single read threw
// "Could not read the actual Stripe fee from the charge." A manual retry
// ~1 minute later succeeded with the real fee (465c), proving the fee
// data exists — it just is not reliably readable on the very first read.
// Stripe creates the balance_transaction asynchronously after the charge
// succeeds, so a short retry loop (not a fallback to the estimate) is
// the correct fix. The estimate (2.9% + 30c) is for display only and is
// NEVER used to settle money.
//
// Attempts, in order, per try:
//   1. PaymentIntent retrieve, expand latest_charge.balance_transaction.
//   2. If latest_charge came back as a string id, or its
//      balance_transaction is a string id, re-fetch the charge directly
//      with expand ['balance_transaction'].
//   3. If there is no latest_charge yet, list charges for the intent.
// Returns { actualFeeCents, chargeId } once the fee is a number, else null
// after 3 attempts (~5s apart, ~10s of waiting total) so the caller can
// record the failure and the admin retry endpoint can try again later.
async function readActualFeeCents(stripe, paymentIntentId) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const pi = await stripe.paymentIntents.retrieve(paymentIntentId, {
      expand: ['latest_charge.balance_transaction'],
    });
    let charge = pi.latest_charge;
    if (typeof charge === 'string') {
      charge = await stripe.charges.retrieve(charge, {
        expand: ['balance_transaction'],
      });
    } else if (charge && typeof charge.balance_transaction === 'string') {
      charge = await stripe.charges.retrieve(charge.id, {
        expand: ['balance_transaction'],
      });
    } else if (!charge) {
      // No charge attached to the intent yet — look it up directly.
      const list = await stripe.charges.list({ payment_intent: paymentIntentId, limit: 1 });
      const found = list.data && list.data[0];
      if (found) {
        charge = await stripe.charges.retrieve(found.id, {
          expand: ['balance_transaction'],
        });
      }
    }
    const balanceTx = charge && charge.balance_transaction;
    if (balanceTx && typeof balanceTx === 'object' && typeof balanceTx.fee === 'number') {
      return {
        actualFeeCents: balanceTx.fee,
        chargeId: typeof charge === 'object' ? charge.id : charge,
      };
    }
    if (attempt < 3) await sleep(5000);
  }
  return null;
}

async function createHostTransfer(stripe, booking) {
  const fresh = loadBookings().find((b) => b.id === booking.id) || booking;
  if (fresh.stripeTransferId) return fresh; // already transferred — do not double-pay
  const listing = loadListings().find((l) => l.id === fresh.listingId);
  if (!listing || !listing.hostStripeAccountId) {
    saveBookingPatch(fresh.id, {
      transferStatus: 'failed',
      transferError: 'No host Connect account on the listing.',
    });
    return { ...fresh, transferStatus: 'failed' };
  }
  try {
    // latest_charge.balance_transaction carries the authoritative fee.
    // It is not reliably populated at webhook time (see
    // readActualFeeCents), so retry the read before giving up — never
    // fall back to the estimate to settle money.
    const feeRead = await readActualFeeCents(stripe, fresh.stripePaymentIntentId);
    if (!feeRead) throw new Error('Could not read the actual Stripe fee from the charge.');
    const { actualFeeCents, chargeId } = feeRead;
    const hostGrossCents = fresh.hostGrossCents ?? fresh.hostAmountCents;
    const hostNetActualCents = actualHostNetCents(hostGrossCents, actualFeeCents);
    const shortfallCents = feeShortfallCents(hostGrossCents, actualFeeCents);
    if (hostNetActualCents <= 0) {
      // Fee ate the whole host share (only possible on a tiny trip).
      // Record it — do not create a $0 transfer and do not hide the shortfall.
      saveBookingPatch(fresh.id, {
        stripeFeeActualCents: actualFeeCents,
        hostNetActualCents: 0,
        feeShortfallCents: shortfallCents,
        transferStatus: 'failed',
        transferError: `Stripe fee (${actualFeeCents}c) met or exceeded the host share (${hostGrossCents}c).`,
      });
      return { ...fresh, transferStatus: 'failed' };
    }
    const transfer = await stripe.transfers.create({
      amount: hostNetActualCents,
      currency: 'usd',
      destination: listing.hostStripeAccountId,
      source_transaction: chargeId,
      metadata: {
        source: 'hoopty',
        booking_id: fresh.id,
        listing_id: fresh.listingId,
        host_gross_cents: String(hostGrossCents),
        stripe_fee_actual_cents: String(actualFeeCents),
        hoopty_fee_cents: String(fresh.hooptyFeeCents),
      },
    });
    const patch = {
      stripeFeeActualCents: actualFeeCents,
      hostNetActualCents,
      feeShortfallCents: shortfallCents,
      stripeTransferId: transfer.id,
      transferStatus: 'transferred',
      transferredAt: new Date().toISOString(),
      // Clear any earlier failure: bk_mwlxhidw kept the stale
      // "Could not read the actual Stripe fee" string even after its
      // retry transferred. A transferred booking has no error.
      transferError: null,
    };
    saveBookingPatch(fresh.id, patch);
    return { ...fresh, ...patch };
  } catch (err) {
    saveBookingPatch(fresh.id, {
      transferStatus: 'failed',
      transferError: err.message,
    });
    return { ...fresh, transferStatus: 'failed', transferError: err.message };
  }
}

// ---------------------------------------------------------------------------
// Public (no Stripe key needed)
// ---------------------------------------------------------------------------
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'hoopty-backend',
    stripeConfigured: Boolean(process.env.STRIPE_SECRET_KEY),
    listings: loadListings().length,
    time: new Date().toISOString(),
  });
});

// Replaces the broken ./_viewer fetch. The live site calls this instead.
app.get('/api/listings', (req, res) => {
  const listings = loadListings().map((l) => ({
    ...l,
    // Never leak a host's Connect account id to the browser.
    hostStripeAccountId: undefined,
    payoutsReady: Boolean(l.hostStripeAccountId),
  }));
  res.json({ ok: true, listings });
});

app.get('/api/listings/:id', (req, res) => {
  const listing = loadListings().find((l) => l.id === req.params.id);
  if (!listing) return res.status(404).json({ ok: false, error: 'Listing not found.' });
  const { hostStripeAccountId, ...pub } = listing;
  res.json({ ok: true, listing: { ...pub, payoutsReady: Boolean(hostStripeAccountId) } });
});

// ---------------------------------------------------------------------------
// Host listings — POST /api/listings
// ---------------------------------------------------------------------------
// Lets a host list a car from the Earn Account form (the app's createCar
// action). Before this endpoint the shim could only return an honest
// error, so no car could ever be listed from the app.
//
// PAYOUTS: a new listing starts with hostStripeAccountId null — payouts
// NOT ready — UNLESS the host has already finished Connect onboarding
// (hosts.json shows onboardingComplete for that email), in which case it
// is linked straight away because onboarding is done. Either way the
// invariant holds: checkout refuses a listing whose host has no Connect
// account (409 host_payouts_not_ready) until onboarding is complete.
// This endpoint NEVER creates a Connect account — the host onboards
// themselves via POST /api/connect/onboard. (Note: a host who onboards
// AFTER listing is not auto-linked yet — see the still-open list.)
//
// The app sends dollars (pricePerDay), a planKeep number (70/80/90),
// fuelType/bodyType, and local-only fields (password, car photo,
// agreement) that are NOT sent to / stored by this endpoint. The listing
// stores cents (pricePerDayCents), matching the existing listing shape.
//
// TEST LISTINGS: testListing is an explicit boolean in the request body
// ONLY (b.testListing === true). The app shim sets it when the host's
// description is marked "TEST LISTING ONLY" — that is the only way an
// app-created listing gets the flag, so a genuine host listing is never
// marked test by default. The flag only drives the TEST banner on
// book.html; it never affects money. (The seed Camry has testListing:
// true in the data file for the same reason.)
function newListingId(listings) {
  let id;
  do {
    id = `car_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  } while (listings.some((l) => l.id === id));
  return id;
}

// Normalise a plan the app may send as a name ("Starter", "Balanced",
// "Top Earner") or as planKeep (70/80/90). Returns the canonical key
// (starter/balanced/top_earner), or null when the value is not a real
// plan — so a bad plan is a 400, never a silent default.
function planKeyFromInput(plan, planKeep) {
  if (planKeep !== undefined && planKeep !== null && planKeep !== '') {
    const pk = Number(planKeep);
    if (pk === 70) return 'starter';
    if (pk === 80) return 'balanced';
    if (pk === 90) return 'top_earner';
    return null;
  }
  if (plan === undefined || plan === null || plan === '') return 'balanced';
  const raw = String(plan).toLowerCase().replace(/[\s-]+/g, '_');
  if (['starter', 'basic', 'balanced', 'top_earner', 'top'].includes(raw)) {
    return planFromString(plan);
  }
  return null;
}

app.post('/api/listings', (req, res) => {
  const b = req.body || {};

  const hostEmail = String(b.hostEmail || b.email || '').trim().toLowerCase();
  const hostName = String(b.hostName || b.ownerName || '').trim();
  const year = Number(b.year);
  const make = String(b.make || '').trim();
  const model = String(b.model || '').trim();
  const location = String(b.location || '').trim();

  // Price: accept cents (pricePerDayCents) or dollars (pricePerDay).
  // Cents wins if both are sent.
  let pricePerDayCents = null;
  if (b.pricePerDayCents !== undefined && b.pricePerDayCents !== null && b.pricePerDayCents !== '') {
    pricePerDayCents = Math.round(Number(b.pricePerDayCents));
  } else if (b.pricePerDay !== undefined && b.pricePerDay !== null && b.pricePerDay !== '') {
    pricePerDayCents = Math.round(Number(b.pricePerDay) * 100);
  }

  const seats = b.seats === undefined || b.seats === null || b.seats === '' ? 5 : Number(b.seats);
  const transmission = String(b.transmission || 'Automatic').trim();
  const fuel = String(b.fuel || b.fuelType || 'Gas').trim();
  const type = String(b.type || b.bodyType || 'Sedan').trim();
  const features = Array.isArray(b.features)
    ? b.features.map((f) => String(f).trim()).filter(Boolean).slice(0, 20)
    : [];
  const description = String(b.description || '').trim().slice(0, 2000);
  const minTripDays = b.minTripDays === undefined || b.minTripDays === null || b.minTripDays === '' ? 1 : Number(b.minTripDays);
  const maxTripDays = b.maxTripDays === undefined || b.maxTripDays === null || b.maxTripDays === '' ? 90 : Number(b.maxTripDays);
  const blockedDates = Array.isArray(b.blockedDates)
    ? b.blockedDates.map((d) => String(d).trim()).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)).slice(0, 365)
    : [];
  const hostPlan = planKeyFromInput(b.hostPlan || b.plan, b.planKeep);

  // Validate — one clear 400 per problem, never a half-saved listing.
  const bad = (msg) => res.status(400).json({ ok: false, error: msg });
  if (!hostEmail || !/^\S+@\S+\.\S+$/.test(hostEmail)) return bad('A valid host email is required.');
  if (!hostName || hostName.length > 100) return bad('Host name is required (max 100 characters).');
  if (!Number.isInteger(year) || year < 1900 || year > 2027) return bad('Year must be between 1900 and 2027.');
  if (!make || make.length > 60) return bad('Make is required (max 60 characters).');
  if (!model || model.length > 60) return bad('Model is required (max 60 characters).');
  if (!location || location.length > 120) return bad('Location is required (max 120 characters).');
  if (!Number.isFinite(pricePerDayCents) || pricePerDayCents < 100 || pricePerDayCents > 100000) {
    return bad('Daily price must be between $1 and $1,000.');
  }
  if (!Number.isInteger(seats) || seats < 1 || seats > 12) return bad('Seats must be between 1 and 12.');
  if (transmission.length > 30) return bad('Transmission is too long (max 30 characters).');
  if (fuel.length > 30) return bad('Fuel type is too long (max 30 characters).');
  if (type.length > 30) return bad('Body type is too long (max 30 characters).');
  if (!Number.isInteger(minTripDays) || minTripDays < 1 || minTripDays > 30) {
    return bad('Minimum trip must be between 1 and 30 days.');
  }
  if (!Number.isInteger(maxTripDays) || maxTripDays < 1 || maxTripDays > 90) {
    return bad('Maximum trip must be between 1 and 90 days.');
  }
  if (minTripDays > maxTripDays) return bad('Minimum trip cannot be longer than the maximum trip.');
  if (hostPlan === null) return bad('Plan must be Starter, Balanced, or Top Earner.');

  const listings = loadListings();
  // Link the host's Connect account only if they already finished
  // onboarding — otherwise payouts stay NOT ready and checkout refuses
  // this car (host_payouts_not_ready) until they onboard.
  const host = loadHosts()[hostEmail];
  const hostStripeAccountId =
    host && host.onboardingComplete && host.stripeAccountId ? host.stripeAccountId : null;

  const listing = {
    id: newListingId(listings),
    createdAt: new Date().toISOString(),
    hostEmail,
    hostName,
    hostPlan,
    hostStripeAccountId,
    year,
    make,
    model,
    location,
    pricePerDayCents,
    seats,
    transmission,
    fuel,
    type,
    features,
    description,
    minTripDays,
    maxTripDays,
    blockedDates,
    // Explicit flag only — see the comment above POST /api/listings.
    // Never derived from free text on the server, never defaulted true.
    testListing: b.testListing === true,
  };
  listings.push(listing);
  saveListings(listings);

  // Never leak a host's Connect account id to the browser.
  const { hostStripeAccountId: _acct, ...pub } = listing;
  res.status(201).json({ ok: true, listing: { ...pub, payoutsReady: Boolean(hostStripeAccountId) } });
});

// ---------------------------------------------------------------------------
// DELETE /api/listings/:id — a host removes ONLY their own listing.
// ---------------------------------------------------------------------------
// Ownership is checked against the listing's hostEmail (the requester
// sends their signed-in host email; anyone else gets 403). SAFE DEFAULT
// ON BOOKINGS: delete is refused (409) while any booking for the car is
// still live — status 'paid' or 'awaiting_payment' with an endDate of
// today or later. Deleting under a live booking would orphan a trip a
// renter already paid for (the webhook would find no listing and the
// transfer would fail with the money sitting on the platform). A trip
// whose endDate has passed does NOT block delete — the money is settled
// and the listing is just history. A future pass could add a proper
// cancel flow instead of blocking on live bookings.
app.delete('/api/listings/:id', (req, res) => {
  const id = req.params.id;
  const hostEmail = String(
    (req.body && (req.body.hostEmail || req.body.email)) || req.query.hostEmail || ''
  ).trim().toLowerCase();
  if (!hostEmail || !/^\S+@\S+\.\S+$/.test(hostEmail)) {
    return res.status(400).json({ ok: false, error: 'A valid host email is required.' });
  }
  const listings = loadListings();
  const listing = listings.find((l) => l.id === id);
  if (!listing) return res.status(404).json({ ok: false, error: 'Listing not found.' });
  if (String(listing.hostEmail || '').toLowerCase() !== hostEmail) {
    return res.status(403).json({ ok: false, error: 'You can only remove your own listing.' });
  }
  const today = new Date().toISOString().slice(0, 10);
  const liveBooking = loadBookings().find(
    (b) =>
      b.listingId === id &&
      (b.status === 'paid' || b.status === 'awaiting_payment') &&
      String(b.endDate || '') >= today
  );
  if (liveBooking) {
    return res.status(409).json({
      ok: false,
      error: 'This car has a live booking — it cannot be removed until that trip is over. Email info@graycodeenterprise.net to cancel it.',
    });
  }
  saveListings(listings.filter((l) => l.id !== id));
  res.json({ ok: true, deletedId: id });
});

// Look up a Checkout Session after the renter returns from Stripe, so the
// success page can show the real payment status (never trust a URL param).
app.get('/api/checkout/session', async (req, res) => {
  const stripe = getStripe(res);
  if (!stripe) return;
  const id = String(req.query.session_id || '');
  if (!id.startsWith('cs_')) {
    return res.status(400).json({ ok: false, error: 'session_id is required.' });
  }
  const session = await stripe.checkout.sessions.retrieve(id);
  // If this session belongs to a booking, attach the booking's fee
  // breakdown — host gross, Stripe fee (actual once the webhook ran,
  // estimate before that), host net, Hoopty's full cut, transfer status.
  // Never leak the host's Connect account id.
  const booking = findBookingByCheckoutSession(id);
  res.json({
    ok: true,
    paymentStatus: session.payment_status,
    amountTotalCents: session.amount_total,
    currency: session.currency,
    customerEmail: (session.customer_details && session.customer_details.email) || null,
    booking: booking
      ? {
          id: booking.id,
          listingId: booking.listingId,
          status: booking.status,
          totalCents: booking.totalCents,
          hostGrossCents: booking.hostGrossCents ?? booking.hostAmountCents,
          hooptyFeeCents: booking.hooptyFeeCents,
          stripeFeeEstimateCents: booking.stripeFeeEstimateCents,
          stripeFeeActualCents: booking.stripeFeeActualCents ?? null,
          hostNetCents: booking.hostNetCents,
          hostNetActualCents: booking.hostNetActualCents ?? null,
          transferStatus: booking.transferStatus || 'pending',
        }
      : null,
  });
});

// Price quote for the booking page — server-authoritative, so the page
// never shows one split and charges another. The Stripe fee here is an
// ESTIMATE (2.9% + 30c); the host's FINAL net is set after payment from
// the actual fee. The renter always pays the trip total only.
app.get('/api/quote', (req, res) => {
  const listing = loadListings().find((l) => l.id === req.query.listingId);
  if (!listing) return res.status(404).json({ ok: false, error: 'Listing not found.' });
  const start = new Date(`${req.query.startDate}T12:00:00`);
  const end = new Date(`${req.query.endDate}T12:00:00`);
  const days = Math.round((end - start) / 86400000);
  if (!Number.isFinite(days) || days < 1 || days > 30) {
    return res.status(400).json({ ok: false, error: 'Trip must be 1–30 days.' });
  }
  const totalCents = tripTotalCents(listing.pricePerDayCents, days);
  const split = splitTrip(totalCents, listing.hostPlan);
  res.json({
    ok: true,
    listingId: listing.id,
    days,
    totalCents,
    totalFormatted: usd(totalCents),
    hostPlan: split.plan,
    hostGrossCents: split.hostGrossCents,
    hooptyFeeCents: split.hooptyFeeCents,
    stripeFeeEstimateCents: split.stripeFeeEstimateCents,
    hostNetCents: split.hostNetCents,
    stripeFeeNote:
      'Estimate only (2.9% + 30c). The host pays the ACTUAL Stripe fee out of their share; the final host net is set after payment.',
  });
});

// Retry a failed host transfer (admin only — protect with an admin key at
// deploy time; not linked from any renter/host page). Safe to call twice:
// createHostTransfer is idempotent once a transfer exists.
app.post('/api/bookings/:id/retry-transfer', async (req, res) => {
  const stripe = getStripe(res);
  if (!stripe) return;
  const booking = loadBookings().find((b) => b.id === req.params.id);
  if (!booking) return res.status(404).json({ ok: false, error: 'Booking not found.' });
  if (booking.status !== 'paid') {
    return res.status(409).json({ ok: false, error: 'Booking is not paid yet — nothing to transfer.' });
  }
  const updated = await createHostTransfer(stripe, booking);
  const fresh = loadBookings().find((b) => b.id === booking.id);
  res.json({
    ok: true,
    bookingId: fresh.id,
    transferStatus: fresh.transferStatus,
    stripeTransferId: fresh.stripeTransferId || null,
    hostNetActualCents: fresh.hostNetActualCents ?? null,
    transferError: fresh.transferError || null,
    _note: updated.transferStatus === 'transferred' ? undefined : 'Transfer still failed — check the error and the Stripe Dashboard.',
  });
});

// Trips — ALWAYS scoped to one signed-in renter. The live site's Trips view
// used to fetch every booking ("Showing all trips for now"); that is the bug
// this endpoint fixes. No email = no trips, never the whole list.
app.get('/api/bookings', (req, res) => {
  const email = String(req.query.email || '').toLowerCase();
  if (!email) {
    return res.status(400).json({ ok: false, error: 'email is required — trips are scoped to the signed-in renter.' });
  }
  const mine = loadBookings()
    .filter((b) => b.renterEmail === email)
    .map((b) => ({ ...b, stripeCheckoutSessionId: undefined }));
  res.json({ ok: true, email, bookings: mine });
});

// Renter Identity status, keyed by the email they signed up with.
app.get('/api/identity/status', (req, res) => {
  const email = String(req.query.email || '').toLowerCase();
  if (!email) return res.status(400).json({ ok: false, error: 'email is required.' });
  const renter = loadRenters()[email];
  res.json({
    ok: true,
    email,
    identityStatus: renter ? renter.identityStatus : 'not_started',
    verifiedAt: renter ? renter.verifiedAt || null : null,
  });
});

// ---------------------------------------------------------------------------
// Stripe Identity — license verification BEFORE first booking
// ---------------------------------------------------------------------------
app.post('/api/identity/start', async (req, res) => {
  const stripe = getStripe(res);
  if (!stripe) return;
  const email = String(req.body.email || '').trim().toLowerCase();
  const fullName = String(req.body.fullName || '').trim();
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ ok: false, error: 'A valid email is required.' });
  }
  const existing = loadRenters()[email];
  if (existing && existing.identityStatus === 'verified') {
    return res.json({ ok: true, alreadyVerified: true, identityStatus: 'verified' });
  }

  // type: document = government ID + selfie match. Stripe hosts the whole
  // capture flow; Hoopty never sees or stores the license photo or selfie.
  const session = await stripe.identity.verificationSessions.create({
    type: 'document',
    metadata: { renter_email: email, renter_name: fullName, source: 'hoopty' },
    return_url: `${FRONTEND_URL}/verify.html?email=${encodeURIComponent(email)}`,
  });
  const renters = loadRenters();
  renters[email] = {
    email,
    identityStatus: 'pending',
    verificationSessionId: session.id,
    updatedAt: new Date().toISOString(),
  };
  saveRenters(renters);
  res.json({ ok: true, verificationSessionId: session.id, url: session.url });
});

// ---------------------------------------------------------------------------
// Stripe Connect — host payout onboarding (Express account)
// ---------------------------------------------------------------------------
app.post('/api/connect/onboard', async (req, res) => {
  const stripe = getStripe(res);
  if (!stripe) return;
  const email = String(req.body.email || '').trim().toLowerCase();
  const hostName = String(req.body.hostName || '').trim();
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ ok: false, error: 'A valid email is required.' });
  }
  const hosts = loadHosts();
  let host = hosts[email];
  if (!host || !host.stripeAccountId) {
    const account = await stripe.accounts.create({
      type: 'express',
      country: 'US',
      email,
      business_type: 'individual',
      capabilities: { card_payments: { requested: true }, transfers: { requested: true } },
      metadata: { source: 'hoopty', host_email: email },
    });
    host = { email, hostName, stripeAccountId: account.id, onboardingComplete: false };
    hosts[email] = host;
    saveHosts(hosts);
  }
  const link = await stripe.accountLinks.create({
    account: host.stripeAccountId,
    refresh_url: `${FRONTEND_URL}/earn.html?onboarding=refresh`,
    return_url: `${FRONTEND_URL}/earn.html?onboarding=done`,
    type: 'account_onboarding',
  });
  res.json({ ok: true, stripeAccountId: host.stripeAccountId, url: link.url });
});

// Host onboarding status (called after the host returns from Stripe).
app.get('/api/connect/status', async (req, res) => {
  const stripe = getStripe(res);
  if (!stripe) return;
  const email = String(req.query.email || '').toLowerCase();
  const host = loadHosts()[email];
  if (!host) return res.json({ ok: true, onboarded: false });
  const account = await stripe.accounts.retrieve(host.stripeAccountId);
  const complete = Boolean(account.charges_enabled && account.payouts_enabled);
  if (complete !== host.onboardingComplete) {
    const hosts = loadHosts();
    hosts[email] = { ...host, onboardingComplete: complete };
    saveHosts(hosts);
  }
  res.json({ ok: true, onboarded: complete, stripeAccountId: host.stripeAccountId });
});

// ---------------------------------------------------------------------------
// Stripe Checkout — collect at booking (separate charge; the host's
// Transfer is created by the webhook after payment — see header comment)
// ---------------------------------------------------------------------------
app.post('/api/checkout', async (req, res) => {
  const stripe = getStripe(res);
  if (!stripe) return;
  const { listingId, startDate, endDate, renterEmail, renterName } = req.body || {};
  const email = String(renterEmail || '').trim().toLowerCase();
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ ok: false, error: 'A valid renter email is required.' });
  }

  // Gate 1 — Identity: no verified license, no booking. The webhook is the
  // source of truth; the local record is only a cache of what Stripe said.
  const renter = loadRenters()[email];
  if (!renter || renter.identityStatus !== 'verified') {
    return res.status(403).json({
      ok: false,
      error: 'identity_required',
      message: 'Verify your driver\u2019s license first. Complete Stripe Identity, then book.',
    });
  }

  // Gate 2 — the listing must exist and its host must have payouts ready.
  const listing = loadListings().find((l) => l.id === listingId);
  if (!listing) return res.status(404).json({ ok: false, error: 'Listing not found.' });
  if (!listing.hostStripeAccountId) {
    return res.status(409).json({
      ok: false,
      error: 'host_payouts_not_ready',
      message: 'This host hasn\u2019t finished Stripe payout setup yet, so bookings are paused for this car.',
    });
  }

  // Days: whole days between pickup and return dates (min 1, max 30).
  const start = new Date(`${startDate}T12:00:00`);
  const end = new Date(`${endDate}T12:00:00`);
  const days = Math.round((end - start) / 86400000);
  if (!Number.isFinite(days) || days < 1 || days > 30) {
    return res.status(400).json({ ok: false, error: 'Trip must be 1–30 days.' });
  }
  const totalCents = tripTotalCents(listing.pricePerDayCents, days);
  const split = splitTrip(totalCents, listing.hostPlan);

  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [
      {
        price_data: {
          currency: 'usd',
          product_data: {
            name: `Hoopty rental — ${listing.year} ${listing.make} ${listing.model} (${days} day${days > 1 ? 's' : ''})`,
            description: `Pickup ${startDate}, return ${endDate}. Host: ${listing.hostName}.`,
          },
          unit_amount: totalCents,
        },
        quantity: 1,
      },
    ],
    // Same as the GCE store: phone collected at checkout.
    phone_number_collection: { enabled: true },
    // Payment methods come from the Dashboard's Checkout settings
    // (card, Link, Cash App, Klarna, Amazon Pay on this account; Apple Pay /
    // Google Pay appear automatically on supported devices).
    customer_email: email,
    metadata: {
      source: 'hoopty',
      listing_id: listing.id,
      booking_days: String(days),
      host_plan: split.plan,
      host_gross_cents: String(split.hostGrossCents),
      hoopty_fee_cents: String(split.hooptyFeeCents),
      stripe_fee_estimate_cents: String(split.stripeFeeEstimateCents),
      host_net_estimate_cents: String(split.hostNetCents),
    },
    payment_intent_data: {
      // SEPARATE charge (not a destination charge): no application_fee and
      // no transfer_data here. The renter pays the trip total to the
      // platform; the host's Transfer is created by the webhook AFTER
      // payment, for hostGross - ACTUAL Stripe fee (see createHostTransfer).
      // That is what makes the host — not Hoopty — pay the processing fee.
      metadata: { source: 'hoopty', listing_id: listing.id },
    },
    success_url: `${FRONTEND_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${FRONTEND_URL}/book.html?listing=${encodeURIComponent(listing.id)}&cancelled=1`,
  });

  const bookings = loadBookings();
  const booking = {
    id: `bk_${Date.now().toString(36)}`,
    listingId: listing.id,
    renterEmail: email,
    renterName: String(renterName || ''),
    startDate,
    endDate,
    days,
    totalCents,
    hostGrossCents: split.hostGrossCents,
    hostAmountCents: split.hostGrossCents, // alias: gross share, before the fee
    hooptyFeeCents: split.hooptyFeeCents,
    stripeFeeEstimateCents: split.stripeFeeEstimateCents,
    hostNetCents: split.hostNetCents, // ESTIMATE — final net set by the webhook
    stripeFeeActualCents: null,
    hostNetActualCents: null,
    feeShortfallCents: 0,
    stripeTransferId: null,
    transferStatus: 'pending',
    hostPlan: split.plan,
    status: 'awaiting_payment',
    stripeCheckoutSessionId: session.id,
    createdAt: new Date().toISOString(),
  };
  bookings.push(booking);
  saveBookings(bookings);

  res.json({
    ok: true,
    bookingId: booking.id,
    checkoutUrl: session.url,
    totalCents,
    totalFormatted: usd(totalCents),
    hostGrossCents: split.hostGrossCents,
    hostAmountCents: split.hostGrossCents, // alias: gross share, before the fee
    hooptyFeeCents: split.hooptyFeeCents,
    stripeFeeEstimateCents: split.stripeFeeEstimateCents,
    hostNetCents: split.hostNetCents, // ESTIMATE — final net set after payment
    transferStatus: 'pending',
  });
});

app.listen(PORT, () => {
  console.log(`hoopty-backend listening on :${PORT} (stripe configured: ${Boolean(process.env.STRIPE_SECRET_KEY)})`);
});
