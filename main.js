const { app, BrowserWindow, shell } = require('electron');
const { start } = require('./server');

let mainWindow;

app.whenReady().then(async () => {
  const port = await start(app.getPath('userData'));

  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 800,
    minHeight: 500,
    title: 'RemoteTail',
    backgroundColor: '#313338',
    autoHideMenuBar: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  mainWindow.loadURL(`http://127.0.0.1:${port}`);

  // open external links in the system browser, not in the app
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.on('closed', () => { mainWindow = null; });
});

app.on('window-all-closed', () => app.quit());
