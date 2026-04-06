const path = require("node:path");
const { getDefaultConfig } = require("expo/metro-config");

const config = getDefaultConfig(__dirname);

function escapeRegExp(value) {
  return value.replace(/[|\\{}()[\]^$+*?.]/g, "\\$&");
}

function pathBlockList(relativePath) {
  const absolutePath = path.resolve(__dirname, relativePath);
  const normalized = escapeRegExp(absolutePath).replace(/\\\\/g, "[\\\\/]");
  return new RegExp(`^${normalized}(?:[\\\\/].*)?$`);
}

config.resolver.blockList = [
  pathBlockList("backend/data"),
  pathBlockList(".venv"),
  pathBlockList(".venv311"),
  pathBlockList(".pytest_cache"),
  pathBlockList("dist"),
  pathBlockList("hosting"),
  pathBlockList(".firebase"),
];

module.exports = config;
