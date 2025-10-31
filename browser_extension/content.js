 // content.js — intercept user clicks and call local backend
 document.addEventListener('click', async (e) => {
   if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
   const a = e.target.closest && e.target.closest('a[href]');
   if (!a) return;
   const url = a.href;
   if (!url || url.startsWith('javascript:')) return;

   e.preventDefault(); // stop immediate navigation
   const overlay = document.createElement('div');
   overlay.textContent = 'Checking link...';
   Object.assign(overlay.style, { position:'fixed', top:'10px', right:'10px', zIndex:2147483647, padding:'8px', background:'#222', color:'#fff', borderRadius:'6px' });
   document.body.appendChild(overlay);

   try {
     const resp = await fetch('http://localhost:8000/check_url', {
       method: 'POST',
       headers: {'Content-Type': 'application/json'},
       body: JSON.stringify({ url })
     });
     const j = await resp.json();
     if (j.is_phishing) {
       alert('Blocked: Suspicious link detected.\nReason: ' + (j.reason || 'unknown'));
     } else {
       window.location.href = url;
     }
   } catch (err) {
     console.error('PhishGuard check failed', err);
     // conservative behaviour: block if the check fails
     alert('PhishGuard check failed — navigation blocked for safety.');
   } finally {
     overlay.remove();
   }
 });

