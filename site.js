// site.js — landing page behaviour (signup + motion). External so the CSP can stay script-src 'self'.
/* ----------------------------------------------------------
   EMAIL SIGNUP
   Leave FORM_ENDPOINT empty and the button opens the visitor's
   mail app — works with zero setup on day one.
   To collect properly, paste a form endpoint here (Formspree,
   Buttondown, ConvertKit, or your own) and it will POST to it.
---------------------------------------------------------- */
const FORM_ENDPOINT = "";
const CONTACT_EMAIL = "hello@blackstonescripts.com";

const input  = document.getElementById('email');
const button = document.getElementById('notify-btn');
const msg    = document.getElementById('msg');

function say(text, ok){
  msg.textContent = text;
  msg.className = 'msg ' + (ok ? 'good' : 'bad');
}

async function submit(){
  const email = input.value.trim();
  if (!email || !email.includes('@') || !email.includes('.')) {
    say('That address is missing an @ or a domain.', false);
    input.focus();
    return;
  }

  if (!FORM_ENDPOINT) {
    window.location.href =
      'mailto:' + CONTACT_EMAIL +
      '?subject=' + encodeURIComponent('Notify me at launch') +
      '&body=' + encodeURIComponent(email);
    say('Opening your mail app.', true);
    return;
  }

  button.disabled = true;
  const original = button.textContent;
  button.textContent = 'Sending…';

  try {
    const res = await fetch(FORM_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ email })
    });
    if (!res.ok) throw new Error(res.status);
    say("You're on the list.", true);
    input.value = '';
  } catch (err) {
    say("That didn't send. Email " + CONTACT_EMAIL + " and I'll add you.", false);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

button.addEventListener('click', submit);
input.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });

/* ----------------------------------------------------------
   MOTION
---------------------------------------------------------- */
const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* boot sequence */
const lines = document.querySelectorAll('#log .line');
if (reduced) {
  lines.forEach(l => l.classList.add('in'));
} else {
  lines.forEach((line, i) => setTimeout(() => line.classList.add('in'), 380 + i * 240));
}

/* scroll reveals */
const reveals = document.querySelectorAll('.reveal');
if (reduced || !('IntersectionObserver' in window)) {
  reveals.forEach(el => el.classList.add('in'));
} else {
  const io = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('in');
        io.unobserve(entry.target);
      }
    });
  }, { rootMargin: '0px 0px -12% 0px', threshold: 0.08 });
  reveals.forEach(el => io.observe(el));
}
