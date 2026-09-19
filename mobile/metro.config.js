// Cấu hình Metro cho monorepo: cho phép mobile/ nạp ../core (@sentinell/core) và
// resolve @noble/* từ node_modules ở gốc workspace. (Expo SDK 52+ tự nhận diện monorepo,
// khai báo tường minh ở đây để chắc chắn.)
const { getDefaultConfig } = require("expo/metro-config");
const path = require("path");

const projectRoot = __dirname;
const workspaceRoot = path.resolve(projectRoot, "..");

const config = getDefaultConfig(projectRoot);
config.watchFolders = [workspaceRoot];
config.resolver.nodeModulesPaths = [
  path.resolve(projectRoot, "node_modules"),
  path.resolve(workspaceRoot, "node_modules"),
];

module.exports = config;
