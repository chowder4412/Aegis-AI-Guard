import * as WebBrowser from 'expo-web-browser';

WebBrowser.maybeCompleteAuthSession();

export const GOOGLE_WEB_CLIENT_ID =
  process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID || '662641033139-5vs6pp0gcal7bnbqlfo82u56r20h26oq.apps.googleusercontent.com';

export const GOOGLE_IOS_CLIENT_ID =
  process.env.EXPO_PUBLIC_GOOGLE_IOS_CLIENT_ID || '662641033139-ho508okt1iah75gshbt1jr332fnkjmu7.apps.googleusercontent.com';

export const GOOGLE_ANDROID_CLIENT_ID =
  process.env.EXPO_PUBLIC_GOOGLE_ANDROID_CLIENT_ID || GOOGLE_WEB_CLIENT_ID;
