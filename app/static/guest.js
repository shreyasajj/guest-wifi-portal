// Guest page helpers: cooldown countdown and approval polling. No framework, ~1 KB.
(function () {
  // Countdown: <span data-countdown="20"> + optional button[data-countdown-enable]
  document.querySelectorAll("[data-countdown]").forEach(function (el) {
    var left = parseInt(el.getAttribute("data-countdown"), 10) || 0;
    var btn = document.querySelector("[data-countdown-enable]");
    if (btn) btn.disabled = left > 0;
    var tick = function () {
      el.textContent = left > 0 ? left + "s" : "now";
      if (left <= 0) { if (btn) btn.disabled = false; return; }
      left -= 1;
      setTimeout(tick, 1000);
    };
    tick();
  });

  // Approval polling: <div data-poll="/waiting/status">
  var poll = document.querySelector("[data-poll]");
  if (poll) {
    var url = poll.getAttribute("data-poll");
    var delay = 2000;
    var check = function () {
      fetch(url, { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.state === "approved" || d.state === "failed") { window.location.href = d.next; return; }
          delay = 2000; setTimeout(check, delay);
        })
        .catch(function () { delay = Math.min(delay * 2, 15000); setTimeout(check, delay); });
    };
    setTimeout(check, delay);
  }

  // Disable submit buttons after the first click to avoid double posts.
  document.querySelectorAll("form[data-once]").forEach(function (f) {
    f.addEventListener("submit", function () {
      f.querySelectorAll("button[type=submit]").forEach(function (b) { setTimeout(function () { b.disabled = true; }, 0); });
    });
  });
})();
