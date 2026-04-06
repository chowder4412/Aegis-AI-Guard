const { spawn } = require("node:child_process");

const expoArgs = process.argv.slice(2);
const env = {
  ...process.env,
  EXPO_NO_DOCTOR: process.env.EXPO_NO_DOCTOR || "1",
};

const child =
  process.platform === "win32"
    ? spawn(
        process.env.ComSpec || "cmd.exe",
        [
          "/d",
          "/s",
          "/c",
          [
            "npx.cmd",
            "-p",
            "node@20",
            "node",
            "node_modules/expo/bin/cli",
            ...expoArgs,
          ]
            .map((arg) => (arg.includes(" ") ? `"${arg}"` : arg))
            .join(" "),
        ],
        { stdio: "inherit", env }
      )
    : spawn(
        "npx",
        ["-p", "node@20", "node", "node_modules/expo/bin/cli", ...expoArgs],
        { stdio: "inherit", env }
      );

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 0);
});
