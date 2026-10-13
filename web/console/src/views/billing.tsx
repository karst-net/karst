// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState, type FormEvent } from "react";
import type { RelayCapDraft } from "@karst-net/api-client";
import { api } from "../api";
import { Failure, Notice, Rows, useMutation, useResource } from "../common";

const currentMonth = () => new Date().toISOString().slice(0, 7);

/** Convert an exact USD decimal string into cents without rounding. */
export function parseUsdMinor(value: string): number | null {
  const match = /^(\d+)(?:\.(\d{1,2}))?$/.exec(value.trim());
  if (!match) return null;
  const whole = Number(match[1]);
  const fractional = Number((match[2] ?? "").padEnd(2, "0"));
  const minor = whole * 100 + fractional;
  return Number.isSafeInteger(minor) ? minor : null;
}

export function formatUsdMinor(minor: number): string {
  return `${(minor / 100).toFixed(2)}`;
}

function reportInterval(month: string) {
  const [year, monthNumber] = month.split("-").map(Number);
  const start = new Date(Date.UTC(year, monthNumber - 1, 1));
  let end = new Date(Date.UTC(year, monthNumber, 1));
  const now = new Date();
  if (end > now) end = now;
  end = new Date(Math.floor(end.getTime() / 60_000) * 60_000);
  return { start: start.toISOString(), end: end.toISOString() };
}

function ErrorMessage({ message }: { message: string }) {
  return <p role="alert">{message}</p>;
}

export function Billing() {
  const [reportMonth, setReportMonth] = useState(currentMonth);
  const [capMonth, setCapMonth] = useState(currentMonth);
  const interval = reportInterval(reportMonth);
  const usage = useResource(async () => {
    const [devices, relays] = await Promise.all([
      api.deviceUsage(interval.start, interval.end),
      api.relayUsage(interval.start, interval.end),
    ]);
    return { devices, relays };
  }, [reportMonth]);
  const alerts = useResource(() => api.relayAlerts(reportMonth), [reportMonth]);
  const payment = useResource(() => api.billingPayment(reportMonth), [reportMonth]);
  const paymentNotices = useResource(() => api.billingPaymentNotices(reportMonth), [reportMonth]);
  const cap = useResource(() => api.relayCap(capMonth), [capMonth]);
  const { message, setMessage, run } = useMutation(cap.reload);
  const { message: paymentMessage, setMessage: setPaymentMessage, run: runPayment } = useMutation(payment.reload);
  const [limit, setLimit] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);

  useEffect(() => {
    setLimit(cap.value?.enabled && cap.value.overage_limit_minor !== undefined
      ? formatUsdMinor(cap.value.overage_limit_minor)
      : "");
    setAcknowledged(cap.value?.acknowledged_interruption ?? false);
  }, [cap.value]);

  const saveCap = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const overage_limit_minor = parseUsdMinor(limit);
    if (overage_limit_minor === null) {
      setMessage("Enter a nonnegative USD amount with at most two decimal places.");
      return;
    }
    if (!acknowledged) {
      setMessage("Acknowledge the relay interruption behavior before saving a cap.");
      return;
    }
    const draft: RelayCapDraft = { period: capMonth, overage_limit_minor, acknowledge_interruption: true };
    setPaymentMessage(undefined);
    await run(() => api.setRelayCap(draft), `Relay spending cap saved for ${capMonth}.`);
  };

  const now = currentMonth();
  const reportError = usage.error;
  const alertError = alerts.error;
  const capError = cap.error;

  return <section>
    <h2>Billing</h2>
    <p className="lede">Usage reports show recorded amounts and coverage. Incomplete coverage means the displayed usage is a lower bound, not a final bill.</p>

    <section aria-labelledby="usage-heading">
      <h3 id="usage-heading">Usage and alerts</h3>
      <label>UTC month for usage and alerts<input aria-label="Usage month" type="month" min={new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth() - 2, 1)).toISOString().slice(0, 7)} max={now} value={reportMonth} onChange={(event) => setReportMonth(event.target.value)} /></label>
      {usage.loading && <p>Loading usage…</p>}
      {reportError && <Failure message={reportError} retry={usage.reload} />}
      {usage.value && <>
        <div className="two-col">
          <article><h4>Device usage</h4><p><strong>{usage.value.devices.complete ? "Complete" : "Incomplete coverage"}</strong></p><p>Eligible device-time in complete intervals: <code>{BigInt(usage.value.devices.device_microseconds).toLocaleString()} µs</code></p></article>
          <article><h4>Managed relay usage</h4><p><strong>{usage.value.relays.complete ? "Complete" : "Lower bound"}</strong></p><p>Reported customer payload: <code>{BigInt(usage.value.relays.reported_bytes).toLocaleString()} bytes</code></p><p>{usage.value.relays.missing_windows.toLocaleString()} missing windows of {usage.value.relays.expected_windows.toLocaleString()} expected</p></article>
        </div>
        {!usage.value.devices.complete && <p>Device coverage is incomplete. Only eligible time from complete intervals is shown.</p>}
        {!usage.value.relays.complete && <p>Relay coverage is incomplete. Reported bytes are a lower bound and do not include missing windows.</p>}
      </>}
      {alerts.loading && <p>Loading billing alerts…</p>}
      {alertError && <ErrorMessage message={alertError} />}
      {alerts.value && <>
        {alerts.value.coverage_warning && <p>{alerts.value.coverage_warning}</p>}
        {alerts.value.alerts.length === 0
          ? <p>No relay usage thresholds have been crossed for {reportMonth}.</p>
          : <Rows head={<><th>Usage target</th><th>Threshold</th><th>Reported bytes</th><th>Threshold bytes</th><th>Coverage</th></>}>
            {alerts.value.alerts.map((alert) => <tr key={`${alert.target}-${alert.threshold_percent}`}>
              <td>{alert.target === "included_allowance" ? "Included relay allowance" : "Spending cap"}</td>
              <td>{alert.threshold_percent}%</td>
              <td>{BigInt(alert.reported_bytes).toLocaleString()}</td>
              <td>{BigInt(alert.threshold_bytes).toLocaleString()}</td>
              <td>{alert.usage_complete ? "Complete" : "Lower bound"}</td>
            </tr>)}
          </Rows>}
      </>}
    </section>

    <section aria-labelledby="invoice-heading">
      <h3 id="invoice-heading">Invoice and payment</h3>
      <p className="lede">Only a finalized invoice can be paid. Paddle adds applicable tax and displays it separately at checkout. Payment status does not change network access.</p>
      <section aria-labelledby="payment-notices-heading">
        <h4 id="payment-notices-heading">Payment notices</h4>
        {paymentNotices.loading && <p>Loading payment notices…</p>}
        {paymentNotices.error && <ErrorMessage message={paymentNotices.error} />}
        {paymentNotices.value && (paymentNotices.value.notices.length === 0
          ? <p>No payment failure notices for {reportMonth}.</p>
          : <ul aria-label="Payment failure notices">
            {paymentNotices.value.notices.map((notice) => <li key={`${notice.period_start}-${notice.created_at}`}>
              <strong>Payment failed for {notice.period_start.slice(0, 7)}.</strong> Your service remains active. Review the invoice and checkout status below.
            </li>)}
          </ul>)}
      </section>
      {payment.loading && <p>Loading invoice…</p>}
      {payment.error && <p role="alert">{payment.error}</p>}
      {payment.value && <>
        <p>Finalized invoice for {reportMonth}: devices <strong>${formatUsdMinor(payment.value.device_minor)}</strong>, managed relay <strong>${formatUsdMinor(payment.value.relay_minor)}</strong>, total <strong>${formatUsdMinor(payment.value.total_minor)} USD before tax</strong>.</p>
        <p>Payment status: <strong>{payment.value.state.replaceAll("_", " ")}</strong>.</p>
        {payment.value.state === "past_due" && <p role="alert"><strong>Payment failed.</strong> Your service remains active during the 14-day grace period. Check this page for updated payment status or use the checkout link below.</p>}
        {payment.value.state === "not_queued" && <button type="button" onClick={() => { setMessage(undefined); void runPayment(() => api.queueBillingPayment(reportMonth), "Paddle checkout request queued. Refresh payment status to see the checkout link."); }}>Prepare Paddle checkout</button>}
        {payment.value.checkout_url && (payment.value.state === "checkout" || payment.value.state === "past_due") && <p><a href={payment.value.checkout_url} target="_blank" rel="noreferrer">Continue to Paddle checkout</a></p>}
        {payment.value.state === "ready" && <p>The checkout request is queued. Refresh after it has been processed.</p>}
        {payment.value.state === "submitting" && <p>Paddle is preparing the checkout.</p>}
        {payment.value.state === "reconcile" && <p>The payment result is being reconciled. Do not submit another payment while this is unresolved.</p>}
        {payment.value.state === "operator_hold" && <p>This payment needs operator review. Contact support before taking another payment action.</p>}
        {payment.value.state === "paid" && <p>Payment received.</p>}
        <button type="button" onClick={() => { void payment.reload(); void paymentNotices.reload(); }}>Refresh payment status</button>
      </>}
    </section>

    <section aria-labelledby="cap-heading">
      <h3 id="cap-heading">Optional relay spending cap</h3>
      <p className="lede">A cap limits managed-relay overage for this account and month. At the limit, managed-relay forwarding can pause; direct peer traffic and device access continue. No cap is applied unless you set one.</p>
      <label>Cap month<input aria-label="Cap month" type="month" min={now} value={capMonth} onChange={(event) => setCapMonth(event.target.value)} /></label>
      {cap.loading && <p>Loading cap…</p>}
      {capError && <ErrorMessage message={capError} />}
      {cap.value && <>
        {cap.value.enabled
          ? <p>Cap is enabled: <strong>${formatUsdMinor(cap.value.overage_limit_minor ?? 0)} USD</strong> overage for {capMonth}. Effective {cap.value.effective_at ? new Date(cap.value.effective_at).toLocaleString() : "at the start of the period"}.</p>
          : <p>No cap is configured for {capMonth}; managed-relay overage is uncapped.</p>}
        <form onSubmit={(event) => void saveCap(event)}>
          <label>Monthly overage limit in USD<input aria-label="Monthly overage limit in USD" type="number" min="0" step="0.01" inputMode="decimal" value={limit} onChange={(event) => setLimit(event.target.value)} placeholder="25.00" /></label>
          <p className="lede">Use up to two decimal places. Amounts and byte budgets truncate down; they are not rounded up.</p>
          <label><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} /> I understand managed-relay connections may stall or disconnect when this cap is reached.</label>
          <div className="actions"><button className="primary" type="submit" disabled={!cap.value}>Save cap</button></div>
        </form>
        {cap.value.enabled && capMonth === now && <p className="lede">A current-period decrease is accepted only after every relay grant has been safely surrendered and consumed usage fits under the lower limit. Clean relay shutdowns return unused credits; an unclean shutdown, unreachable relay, or failed surrender leaves its full reservation in place through period end.</p>}
      </>}
      <Notice message={paymentMessage ?? message} />
    </section>
  </section>;
}
