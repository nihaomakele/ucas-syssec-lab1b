const token = location.hash.slice(1);
const form = document.querySelector("#connection");
const statusLine = document.querySelector("#connection-state");
const files = document.querySelector("#files");
const picker = document.querySelector("#picker");
const jobs = document.querySelector("#jobs");
let connected = false;
let changing = false;
let active = 0;
const pending = [];

async function request(path, options = {}) {
  options.headers = { ...options.headers, "X-Lab-Token": token };
  const response = await fetch(path, options);
  if (!response.ok) throw new Error((await response.json()).error);
  return response;
}

function buttons() {
  form.querySelector("button[type=submit]").disabled = connected || changing;
  document.querySelector("#disconnect").disabled = !connected || changing || Boolean(active + pending.length);
  for (const id of ["refresh", "upload", "download"]) {
    document.querySelector("#" + id).disabled = !connected || changing;
  }
}

async function refresh() {
  try {
    const data = await (await request("/api/files")).json();
    files.replaceChildren();
    for (const item of data.files) {
      const row = files.insertRow();
      const input = row.insertCell().appendChild(document.createElement("input"));
      input.type = "checkbox";
      input.value = item.name;
      input.setAttribute("aria-label", "选择 " + item.name);
      row.insertCell().textContent = item.name;
      row.insertCell().textContent = item.size;
    }
    document.querySelector("#empty").textContent = data.files.length ? "" : "服务器目录为空。";
  } catch (error) {
    statusLine.textContent = error.message;
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  changing = true;
  buttons();
  try {
    const data = Object.fromEntries(new FormData(form));
    data.port = Number(data.port);
    const account = await (await request("/api/connect", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data),
    })).json();
    connected = true;
    form.elements.password.value = "";
    statusLine.textContent = `已连接 · ${data.username} · ${account.tier === "VIP" ? "VIP" : "普通"} · ${account.tls}`;
    await refresh();
  } catch (error) {
    statusLine.textContent = error.message;
  } finally {
    changing = false;
    buttons();
  }
});

document.querySelector("#disconnect").onclick = async () => {
  changing = true;
  buttons();
  try {
    await request("/api/disconnect", { method: "POST" });
    connected = false;
    files.replaceChildren();
    document.querySelector("#empty").textContent = "连接后在此显示文件。";
    statusLine.textContent = "未连接";
  } catch (error) {
    statusLine.textContent = error.message;
  } finally {
    changing = false;
    buttons();
  }
};

function enqueue(name, file) {
  const item = jobs.appendChild(document.createElement("li"));
  const label = (file ? "上传 " : "下载 ") + name;
  item.textContent = label + " · 排队中";
  pending.push({ name, file, item, label });
  pump();
}

async function transfer(job) {
  const { name, file, item, label } = job;
  item.textContent = label + " · 传输中";
  try {
    const path = "/api/file/" + encodeURIComponent(name);
    if (file) {
      await request(path, { method: "POST", body: file });
      item.textContent = label + " · 完成";
    } else {
      const url = URL.createObjectURL(await (await request(path)).blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = name;
      link.textContent = "保存文件";
      link.addEventListener("click", () => {
        setTimeout(() => URL.revokeObjectURL(url), 1500);
        setTimeout(() => { item.textContent = label + " · 已发起保存"; }, 1500);
      }, { once: true });
      item.textContent = label + " · 接收完成 ";
      item.append(link);
    }
  } catch (error) {
    item.textContent = label + " · " + error.message;
  } finally {
    active -= 1;
    pump();
    if (!active && !pending.length) refresh();
  }
}

function pump() {
  while (active < 3 && pending.length) {
    active += 1;
    transfer(pending.shift());
  }
  buttons();
}

document.querySelector("#refresh").onclick = refresh;
document.querySelector("#upload").onclick = () => picker.click();
picker.onchange = () => {
  const chosen = [...picker.files];
  const names = new Set(chosen.map((file) => file.name.toLowerCase()));
  if (names.size !== chosen.length) {
    statusLine.textContent = "同一批次不能上传同名文件。";
  } else {
    for (const file of chosen) enqueue(file.name, file);
  }
  picker.value = "";
};
document.querySelector("#download").onclick = () => {
  for (const input of files.querySelectorAll("input:checked")) enqueue(input.value);
};
