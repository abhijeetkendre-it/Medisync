import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getAnalytics } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-analytics.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";
import { getFirestore, initializeFirestore } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";
import { getStorage } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-storage.js";

const firebaseConfig = {
  apiKey: "AIzaSyCC7HwlFSHRoITCCtcsd2hm9DrR030Yu34",
  authDomain: "medisync-f7bd2.firebaseapp.com",
  projectId: "medisync-f7bd2",
  storageBucket: "medisync-f7bd2.firebasestorage.app",
  messagingSenderId: "201981109742",
  appId: "1:201981109742:web:807d1e62f7b920fe3e9aff",
  measurementId: "G-5DX985CQ57"
};

const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);
const auth = getAuth(app);
const db = initializeFirestore(app, {
  experimentalForceLongPolling: true
});
const storage = getStorage(app);

export { auth, db, storage, app };