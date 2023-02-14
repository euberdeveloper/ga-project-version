import * as path from 'path';

// TODO: find a way to use __dirname and __filename in esm with jest
// export const ASSETS_PATH = path.join(__dirname, '../assets');
export const ASSETS_PATH = path.join(process.cwd(), 'test', 'assets');
