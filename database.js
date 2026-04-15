const { initializeApp } = require('firebase/app');
const { getFirestore, collection, doc, getDoc, getDocs, setDoc, updateDoc, query, where, addDoc, deleteDoc } = require('firebase/firestore');

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
const db = getFirestore(app);

module.exports = {
    db, collection, doc, getDoc, getDocs, setDoc, updateDoc, query, where, addDoc, deleteDoc
};
