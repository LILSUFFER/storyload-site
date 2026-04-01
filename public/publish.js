(function() {
  var form = document.getElementById("publish-form");
  var dzInput = document.getElementById("video-input");
  var dz = document.getElementById("dropzone");
  var dzContent = document.getElementById("dz-content");
  var progressWrap = document.getElementById("progress-wrap");
  var progressFill = document.getElementById("progress-fill");
  var progressPct = document.getElementById("progress-pct");
  var progressLabel = document.getElementById("progress-label-text");
  var submitBtn = document.getElementById("submit-btn");
  var resultBox = document.getElementById("result-box");
  var platformSelect = document.getElementById("platform-select");

  function showFile(input) {
    var f = input.files[0];
    if (!f) return;
    var mb = (f.size / (1024 * 1024)).toFixed(1);
    dz.classList.add("has-file");
    dzContent.innerHTML = '<p style="color:#00E87A;font-weight:600;">' + f.name + '</p><small>' + mb + ' MB</small>';
  }
  window.showFile = showFile;

  dz.addEventListener("dragover", function(e) { e.preventDefault(); dz.classList.add("over"); });
  dz.addEventListener("dragleave", function() { dz.classList.remove("over"); });
  dz.addEventListener("drop", function(e) {
    e.preventDefault(); dz.classList.remove("over");
    var f = e.dataTransfer.files[0];
    if (f && f.type.startsWith("video/")) {
      var dt = new DataTransfer(); dt.items.add(f); dzInput.files = dt.files;
      showFile(dzInput);
    }
  });

  form.addEventListener("submit", function(e) {
    e.preventDefault();
    var file = dzInput.files[0];
    if (!file) { alert("Please select a video file."); return; }
    var platform = platformSelect.value;
    var isYT = platform === "youtube";
    submitBtn.disabled = true;
    submitBtn.textContent = "Publishing...";
    progressWrap.style.display = "block";
    progressLabel.textContent = isYT ? "Uploading to YouTube..." : "Uploading to TikTok...";
    resultBox.style.display = "none";

    var data = new FormData(form);
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/publish");

    xhr.upload.onprogress = function(ev) {
      if (ev.lengthComputable) {
        var pct = Math.round((ev.loaded / ev.total) * (isYT ? 90 : 85));
        progressFill.style.width = pct + "%";
        progressPct.textContent = pct + "%";
        if (isYT && pct >= 90) progressLabel.textContent = "Processing on YouTube...";
        if (!isYT && pct >= 85) progressLabel.textContent = "Sending to TikTok...";
      }
    };

    xhr.onload = function() {
      progressFill.style.width = "100%";
      progressPct.textContent = "100%";
      submitBtn.disabled = false;
      submitBtn.textContent = isYT ? "Publish to YouTube" : "Post to TikTok";
      var resp;
      try { resp = JSON.parse(xhr.responseText); } catch(err) { resp = { error: xhr.responseText }; }
      progressWrap.style.display = "none";
      resultBox.style.display = "block";

      if (xhr.status < 400 && resp.ok) {
        if (resp.platform === "youtube" && resp.videoId) {
          var privacyBadge = {
            "public": '<span style="color:#34D59A">● Public</span>',
            "unlisted": '<span style="color:#A7DDFF">● Unlisted</span>',
            "private": '<span style="color:#888">● Private</span>',
          }[resp.privacyStatus] || '<span style="color:#888">● ' + (resp.privacyStatus || "Private") + '</span>';

          resultBox.innerHTML =
            '<div class="result-success">' +
            '<h3>✓ Published to YouTube!</h3>' +
            '<p style="margin:8px 0 4px">Video ID: <code style="background:rgba(255,255,255,.08);padding:2px 8px;border-radius:4px">' + resp.videoId + '</code></p>' +
            '<p style="margin:4px 0 12px">Privacy: ' + privacyBadge + '</p>' +
            '<a href="' + resp.url + '" target="_blank" rel="noopener" class="btn-primary" style="display:inline-block;margin-top:4px">▶ Open on YouTube</a>' +
            (resp.privacyStatus === "private" ? '<p style="margin-top:12px;font-size:12px;color:#888">Video is private — change visibility in YouTube Studio.</p>' : '') +
            '</div>';
        } else if (resp.platform === "tiktok") {
          resultBox.innerHTML =
            '<div class="result-success">' +
            '<h3>✓ Posted to TikTok!</h3>' +
            '<p style="margin:8px 0">Your video was submitted to TikTok for processing. It will appear in your account shortly.</p>' +
            (resp.publishId ? '<p><code style="background:rgba(255,255,255,.08);padding:2px 8px;border-radius:4px;font-size:12px">Publish ID: ' + resp.publishId + '</code></p>' : '') +
            '<p style="margin-top:12px;font-size:12px;color:var(--muted)">Check your TikTok inbox — you\'ll get a notification when the upload is complete.</p>' +
            '</div>';
        } else {
          resultBox.innerHTML =
            '<div class="result-success"><h3>✓ Video Published!</h3>' +
            '<p>Your video has been submitted successfully.</p></div>';
        }
      } else {
        resultBox.innerHTML = '<div class="result-error"><p><strong>Error:</strong> ' + (resp.error || "Unknown error") + '</p></div>';
      }
    };

    xhr.onerror = function() {
      progressWrap.style.display = "none";
      resultBox.style.display = "block";
      resultBox.innerHTML = '<div class="result-error"><p>Network error. Please try again.</p></div>';
      submitBtn.disabled = false;
      submitBtn.textContent = isYT ? "Publish to YouTube" : "Post to TikTok";
    };
    xhr.send(data);
  });
})();
