(function() {
  var form = document.getElementById("publish-form");
  var dzInput = document.getElementById("video-input");
  var dz = document.getElementById("dropzone");
  var dzContent = document.getElementById("dz-content");
  var progressWrap = document.getElementById("progress-wrap");
  var progressFill = document.getElementById("progress-fill");
  var progressPct = document.getElementById("progress-pct");
  var submitBtn = document.getElementById("submit-btn");
  var resultBox = document.getElementById("result-box");

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
    submitBtn.disabled = true;
    submitBtn.textContent = "Publishing...";
    progressWrap.style.display = "block";
    resultBox.style.display = "none";

    var data = new FormData(form);
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/publish");

    xhr.upload.onprogress = function(ev) {
      if (ev.lengthComputable) {
        var pct = Math.round((ev.loaded / ev.total) * 85);
        progressFill.style.width = pct + "%";
        progressPct.textContent = pct + "%";
      }
    };

    xhr.onload = function() {
      progressFill.style.width = "100%";
      progressPct.textContent = "100%";
      submitBtn.disabled = false;
      submitBtn.textContent = "Publish Video";
      var resp;
      try { resp = JSON.parse(xhr.responseText); } catch(e) { resp = { error: xhr.responseText }; }
      progressWrap.style.display = "none";
      resultBox.style.display = "block";
      if (xhr.status < 400 && resp.ok) {
        resultBox.innerHTML = '<div class="result-success"><h3>✓ Video Published!</h3><p>Your video has been submitted to TikTok for processing.</p>' +
          (resp.publishId ? '<code>Publish ID: ' + resp.publishId + '</code>' : '') +
          '<p style="margin-top:12px;font-size:12px;">Sandbox mode: visible only to your test account.</p></div>';
      } else {
        resultBox.innerHTML = '<div class="result-error"><p><strong>Error:</strong> ' + (resp.error || "Unknown error") + '</p></div>';
      }
    };
    xhr.onerror = function() {
      progressWrap.style.display = "none";
      resultBox.style.display = "block";
      resultBox.innerHTML = '<div class="result-error"><p>Network error. Please try again.</p></div>';
      submitBtn.disabled = false;
      submitBtn.textContent = "Publish Video";
    };
    xhr.send(data);
  });
})();
