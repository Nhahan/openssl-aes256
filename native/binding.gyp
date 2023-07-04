{
  "targets": [
    {
      "target_name": "addon",
      "sources": ["addon.c"],
      "include_dirs": ["<!(node -p \"require('node-addon-api').include\")"],
      "libraries": [],
      "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"]
    }
  ]
}