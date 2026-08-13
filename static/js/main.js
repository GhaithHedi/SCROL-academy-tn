/* أكاديمية SCROL — main.js */
(function () {
  "use strict";

  /* ---- persist <details> open/closed state across page reloads ----
     Admin content management nests forms inside <details> (course →
     lesson edit → resources). Every save/delete/move is a normal form
     POST, so the page reloads and every <details> would snap shut,
     forcing a re-click to get back to where you were. Any <details>
     with an id is remembered in sessionStorage and re-opened here. */
  (function () {
    var KEY = "tafawok_details_open";
    var store;
    try { store = JSON.parse(sessionStorage.getItem(KEY) || "{}"); } catch (e) { store = {}; }
    var tracked = document.querySelectorAll("details[id]");
    var deepest = null, deepestDepth = -1;
    tracked.forEach(function (d) {
      if (store[d.id]) {
        d.open = true;
        var depth = 0, p = d;
        while (p) { depth++; p = p.parentElement; }
        if (depth > deepestDepth) { deepestDepth = depth; deepest = d; }
      }
      d.addEventListener("toggle", function () {
        var current;
        try { current = JSON.parse(sessionStorage.getItem(KEY) || "{}"); } catch (e) { current = {}; }
        if (d.open) current[d.id] = true; else delete current[d.id];
        try { sessionStorage.setItem(KEY, JSON.stringify(current)); } catch (e) {}
      });
    });
    if (deepest) {
      setTimeout(function () { deepest.scrollIntoView({ block: "center" }); }, 30);
    }
  })();

  /* ---- mobile nav ---- */
  var burger = document.getElementById("navBurger");
  var links = document.getElementById("navLinks");
  if (burger && links) {
    burger.addEventListener("click", function () {
      var open = links.classList.toggle("open");
      burger.setAttribute("aria-expanded", open ? "true" : "false");
    });
    links.addEventListener("click", function (e) {
      if (e.target.tagName === "A") {
        links.classList.remove("open");
        burger.setAttribute("aria-expanded", "false");
      }
    });
  }

  /* ---- app sidebar (student shell) ---- */
  var appToggle = document.getElementById("appSidebarToggle");
  var appSidebar = document.getElementById("appSidebar");
  var appBackdrop = document.getElementById("appSidebarBackdrop");
  if (appToggle && appSidebar && appBackdrop) {
    function closeAppSidebar() {
      appSidebar.classList.remove("open");
      appBackdrop.classList.remove("open");
      appToggle.setAttribute("aria-expanded", "false");
    }
    appToggle.addEventListener("click", function () {
      var open = appSidebar.classList.toggle("open");
      appBackdrop.classList.toggle("open", open);
      appToggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    appBackdrop.addEventListener("click", closeAppSidebar);
    appSidebar.addEventListener("click", function (e) {
      if (e.target.closest("a")) closeAppSidebar();
    });
  }

  /* ---- AI tutor chat widget ---- */
  var aiFab = document.getElementById("aiChatFab");
  var aiPanel = document.getElementById("aiChatPanel");
  var aiClose = document.getElementById("aiChatClose");
  var aiBody = document.getElementById("aiChatBody");
  var aiForm = document.getElementById("aiChatForm");
  var aiInput = document.getElementById("aiChatInput");
  var AI_HISTORY_KEY = "tafawok_ai_history";
  var AI_OPEN_KEY = "tafawok_ai_open";

  function aiStoreGet(key, fallback) {
    try {
      var raw = sessionStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (e) { return fallback; }
  }
  function aiStoreSet(key, value) {
    try { sessionStorage.setItem(key, JSON.stringify(value)); } catch (e) {}
  }

  // Clear the saved conversation whenever the user logs out, wherever the
  // logout link appears (student topbar, admin topbar, guest/admin header).
  document.addEventListener("click", function (e) {
    var link = e.target.closest('a[href$="/logout"]');
    if (link) {
      try {
        sessionStorage.removeItem(AI_HISTORY_KEY);
        sessionStorage.removeItem(AI_OPEN_KEY);
      } catch (err) {}
    }
  });

  if (aiFab && aiPanel && aiForm && aiInput && aiBody) {
    var aiHistory = aiStoreGet(AI_HISTORY_KEY, []);
    var aiBusy = false;

    function aiAddMsg(text, who) {
      var div = document.createElement("div");
      div.className = "ai-msg " + (who === "user" ? "ai-msg-user" : "ai-msg-bot");
      div.textContent = text;
      aiBody.appendChild(div);
      aiBody.scrollTop = aiBody.scrollHeight;
      return div;
    }

    // Restore the saved conversation instead of the default greeting.
    if (aiHistory.length) {
      aiBody.innerHTML = "";
      aiHistory.forEach(function (m) {
        aiAddMsg(m.content, m.role === "user" ? "user" : "bot");
      });
    }

    function aiSetOpen(open) {
      aiPanel.hidden = !open;
      aiFab.setAttribute("aria-expanded", open ? "true" : "false");
      aiStoreSet(AI_OPEN_KEY, open);
      if (open) aiInput.focus();
    }
    function aiToggle() { aiSetOpen(!!aiPanel.hidden); }

    aiFab.addEventListener("click", aiToggle);
    if (aiClose) aiClose.addEventListener("click", function () { aiSetOpen(false); });

    if (aiStoreGet(AI_OPEN_KEY, false)) aiSetOpen(true);

    aiForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var text = aiInput.value.trim();
      if (!text || aiBusy) return;
      aiInput.value = "";
      aiAddMsg(text, "user");
      aiHistory.push({ role: "user", content: text });
      aiStoreSet(AI_HISTORY_KEY, aiHistory);
      var typing = aiAddMsg("يكتب...", "bot");
      typing.classList.add("ai-msg-typing");
      aiBusy = true;

      fetch("/api/ai-chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: aiHistory,
          lesson_id: window.AI_LESSON_ID || null
        })
      })
        .then(function (r) { return r.json().then(function (data) { return { ok: r.ok, data: data }; }); })
        .then(function (res) {
          typing.remove();
          if (res.ok && res.data.reply) {
            aiAddMsg(res.data.reply, "bot");
            aiHistory.push({ role: "assistant", content: res.data.reply });
            aiStoreSet(AI_HISTORY_KEY, aiHistory);
          } else {
            aiAddMsg(res.data.error || "حدث خطأ، حاول مجددًا.", "bot");
          }
        })
        .catch(function () {
          typing.remove();
          aiAddMsg("تعذّر الاتصال بالخادم — تحقّق من اتصالك بالإنترنت.", "bot");
        })
        .finally(function () { aiBusy = false; });
    });
  }

  /* ---- Pomodoro technique ----
     State lives in sessionStorage as a wall-clock deadline (not a tick
     counter), so it survives page navigation and stays correct even if the
     tab was throttled/inactive: remaining time is always recomputed from
     Date.now() vs. the stored deadline rather than decremented in place. */
  (function () {
    var pomodoroWidget = document.getElementById("pomodoroWidget");
    if (!pomodoroWidget) return; // not a student page

    var KEY = "tafawok_pomodoro";
    var TICK_MS = 1000;
    var tickTimer = null;
    var audioCtx = null;
    var STR = window.POMODORO_STRINGS || {};

    function loadState() {
      try {
        var raw = sessionStorage.getItem(KEY);
        return raw ? JSON.parse(raw) : null;
      } catch (e) { return null; }
    }
    function saveState(state) {
      try {
        if (state) sessionStorage.setItem(KEY, JSON.stringify(state));
        else sessionStorage.removeItem(KEY);
      } catch (e) {}
    }

    function fmtTime(ms) {
      var total = Math.max(0, Math.ceil(ms / 1000));
      var m = Math.floor(total / 60);
      var s = total % 60;
      return (m < 10 ? "0" : "") + m + ":" + (s < 10 ? "0" : "") + s;
    }

    function beep() {
      try {
        if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        var now = audioCtx.currentTime;
        [0, 0.35, 0.7].forEach(function (offset) {
          var osc = audioCtx.createOscillator();
          var gain = audioCtx.createGain();
          osc.type = "sine";
          osc.frequency.value = 880;
          gain.gain.setValueAtTime(0.0001, now + offset);
          gain.gain.exponentialRampToValueAtTime(0.25, now + offset + 0.02);
          gain.gain.exponentialRampToValueAtTime(0.0001, now + offset + 0.3);
          osc.connect(gain).connect(audioCtx.destination);
          osc.start(now + offset);
          osc.stop(now + offset + 0.32);
        });
      } catch (e) {}
    }

    function showBanner(text) {
      var el = document.getElementById("pomodoroBanner");
      if (!el) {
        el = document.createElement("div");
        el.id = "pomodoroBanner";
        el.className = "pomodoro-banner";
        document.body.appendChild(el);
      }
      el.textContent = text;
      requestAnimationFrame(function () { el.classList.add("pomodoro-banner-show"); });
      clearTimeout(el._hideTimer);
      el._hideTimer = setTimeout(function () {
        el.classList.remove("pomodoro-banner-show");
      }, 2000);
    }

    function startSession(workMin, breakMin) {
      saveState({
        phase: "work",
        workMin: workMin,
        breakMin: breakMin,
        deadline: Date.now() + workMin * 60000
      });
      render();
    }

    function stopSession() {
      saveState(null);
      render();
    }

    function pauseSession() {
      var state = loadState();
      if (!state || state.paused) return;
      state.paused = true;
      state.remainingMs = state.deadline - Date.now();
      saveState(state);
      render();
    }

    function resumeSession() {
      var state = loadState();
      if (!state || !state.paused) return;
      state.deadline = Date.now() + state.remainingMs;
      delete state.paused;
      delete state.remainingMs;
      saveState(state);
      render();
    }

    function advancePhase(state) {
      if (state.phase === "work") {
        beep();
        showBanner(STR.workDone || "");
        state.phase = "break";
        state.deadline = Date.now() + state.breakMin * 60000;
      } else {
        beep();
        showBanner(STR.breakDone || "");
        state.phase = "work";
        state.deadline = Date.now() + state.workMin * 60000;
      }
      saveState(state);
    }

    function updateDisplays(state) {
      var remaining = state.paused ? state.remainingMs : (state.deadline - Date.now());
      var phaseLabel = state.phase === "work" ? STR.phaseWork : STR.phaseBreak;
      document.querySelectorAll('[data-pomo="time"]').forEach(function (el) { el.textContent = fmtTime(remaining); });
      document.querySelectorAll('[data-pomo="phase"]').forEach(function (el) { el.textContent = phaseLabel || ""; });
      document.querySelectorAll('[data-pomo="pause"]').forEach(function (el) {
        el.textContent = state.paused ? (STR.resume || "") : (STR.pause || "");
      });
    }

    function tick() {
      var state = loadState();
      if (!state) { clearInterval(tickTimer); tickTimer = null; return; }
      if (!state.paused && state.deadline - Date.now() <= 0) {
        advancePhase(state);
        state = loadState();
      }
      updateDisplays(state);
    }

    function render() {
      var state = loadState();
      var active = !!state;
      pomodoroWidget.hidden = !(active || window.POMODORO_FORCE_SHOW === true);
      document.querySelectorAll('[data-pomo="active-view"]').forEach(function (el) { el.hidden = !active; });
      document.querySelectorAll('[data-pomo="start-view"]').forEach(function (el) { el.hidden = active; });
      if (active) {
        updateDisplays(state);
        if (!tickTimer) tickTimer = setInterval(tick, TICK_MS);
      } else if (tickTimer) {
        clearInterval(tickTimer);
        tickTimer = null;
      }
    }

    document.querySelectorAll("[data-pomo-preset]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        startSession(parseInt(btn.getAttribute("data-work"), 10), parseInt(btn.getAttribute("data-break"), 10));
      });
    });
    document.querySelectorAll('[data-pomo="pause"]').forEach(function (btn) {
      btn.addEventListener("click", function () {
        var state = loadState();
        if (state && state.paused) resumeSession(); else pauseSession();
      });
    });
    document.querySelectorAll('[data-pomo="stop"]').forEach(function (btn) {
      btn.addEventListener("click", stopSession);
    });

    var workSlider = document.getElementById("pomodoroWorkSlider");
    var breakSlider = document.getElementById("pomodoroBreakSlider");
    var workVal = document.getElementById("pomodoroWorkVal");
    var breakVal = document.getElementById("pomodoroBreakVal");
    var customToggle = document.getElementById("pomodoroCustomToggle");
    var slidersBox = document.getElementById("pomodoroSliders");
    var customStart = document.getElementById("pomodoroCustomStart");
    if (customToggle && slidersBox) {
      customToggle.addEventListener("click", function () { slidersBox.hidden = !slidersBox.hidden; });
    }
    if (workSlider && workVal) {
      workSlider.addEventListener("input", function () { workVal.textContent = workSlider.value; });
    }
    if (breakSlider && breakVal) {
      breakSlider.addEventListener("input", function () { breakVal.textContent = breakSlider.value; });
    }
    if (customStart) {
      customStart.addEventListener("click", function () {
        startSession(parseInt(workSlider.value, 10), parseInt(breakSlider.value, 10));
      });
    }

    var pomodoroFab = document.getElementById("pomodoroFab");
    var pomodoroPanel = document.getElementById("pomodoroPanel");
    var pomodoroClose = document.getElementById("pomodoroClose");
    if (pomodoroFab && pomodoroPanel) {
      pomodoroFab.addEventListener("click", function () {
        pomodoroPanel.hidden = !pomodoroPanel.hidden;
        pomodoroFab.setAttribute("aria-expanded", pomodoroPanel.hidden ? "false" : "true");
      });
    }
    if (pomodoroClose && pomodoroPanel) {
      pomodoroClose.addEventListener("click", function () { pomodoroPanel.hidden = true; });
    }

    render();
  })();

  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---- reveal on scroll ---- */
  var revealEls = document.querySelectorAll(".reveal");
  if (reduced || !("IntersectionObserver" in window)) {
    revealEls.forEach(function (el) { el.classList.add("in"); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("in");
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });
    revealEls.forEach(function (el) { io.observe(el); });
  }

  /* ---- count-up stats (chalkboard) ---- */
  var counters = document.querySelectorAll(".chalk-num[data-count]");
  function animate(el) {
    var target = parseInt(el.getAttribute("data-count"), 10);
    if (isNaN(target) || target <= 0) return;
    var start = null, dur = 1200;
    function step(ts) {
      if (!start) start = ts;
      var p = Math.min((ts - start) / dur, 1);
      el.textContent = Math.floor(p * target);
      if (p < 1) requestAnimationFrame(step);
      else el.textContent = target;
    }
    requestAnimationFrame(step);
  }
  if (!reduced && "IntersectionObserver" in window && counters.length) {
    var cio = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          animate(entry.target);
          cio.unobserve(entry.target);
        }
      });
    }, { threshold: 0.5 });
    counters.forEach(function (el) { cio.observe(el); });
  }
})();
