const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');
const { GoogleGenAI } = require('@google/genai');
const { db, collection, doc, getDoc, getDocs, setDoc, updateDoc, query, where, addDoc, deleteDoc } = require('./database');
const nodemailer = require('nodemailer');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Set up node mailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// HTML Template for OTP Emails
function generateOtpEmailHtml(otp) {
    return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1e293b; max-width: 600px; padding: 20px;">
        <img src="https://medisync-blue.vercel.app/email-logo.png" alt="Medisync Logo" style="max-height: 60px; margin-bottom: 25px; display: block;">
        <p style="font-size: 16px; font-weight: bold; margin-bottom: 20px;">Hi,</p>
        
        <div style="background-color: #2b3954; color: #ffffff; padding: 24px; border-radius: 8px; margin: 24px 0; font-size: 16px; line-height: 1.5;">
            <span style="color: #f59e0b; font-size: 20px; font-weight: bold;">${otp}</span> is your OTP (One Time Password) 
            to login to Medisync. OTP will be valid for 10 minutes. Please do not share it with anyone.
        </div>
        
        <p style="font-size: 15px; color: #64748b; line-height: 1.5; margin-bottom: 40px;">
            Didn't request for the OTP? No issue.<br>
            Someone might have entered your email by mistake. If you don't feel this way, 
            kindly contact us at +91 98342 49455.
        </p>
        
        <div style="display: flex; gap: 10px;">
            <a href="#" style="margin-right: 10px; text-decoration: none;">
                <img src="https://upload.wikimedia.org/wikipedia/commons/3/3c/Download_on_the_App_Store_Badge.svg" alt="Download on the App Store" height="40">
            </a>
            <a href="#" style="text-decoration: none;">
                <img src="https://upload.wikimedia.org/wikipedia/commons/7/78/Google_Play_Store_badge_EN.svg" alt="Get it on Google Play" height="40">
            </a>
        </div>
    </div>
    `;
}

const DEFAULT_DOCTOR_EMAIL = 'testdoc@gmail.com';
const DEFAULT_DOCTOR_PASS = 'Doc@4321';

const ADMIN_USERNAME = 'admin-medisync';
const ADMIN_PASSWORD = 'Qwer@321';

// Middleware
app.use(cors());
app.use(express.json());

// Serve static frontend files from current directory
app.use(express.static(__dirname, { extensions: ['html'] }));

// --- ROUTES ---

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        const usersRef = collection(db, 'users');
        const q = query(usersRef, where("email", "==", email));
        const querySnapshot = await getDocs(q);

        if (!querySnapshot.empty) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpRef = collection(db, 'otps');
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        await addDoc(otpRef, {
            email: email,
            otp: otp,
            type: 'signup',
            signupData: { name, email, password: hashedPassword, role },
            expiresAt: new Date(Date.now() + 10 * 60000) // 10 mins
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Medisync - Signup Verification OTP',
            html: generateOtpEmailHtml(otp)
        };

        try {
            await transporter.sendMail(mailOptions);
        } catch (mailError) {
            console.error("Mail error:", mailError.message);
            return res.status(500).json({ message: 'Failed to send OTP email. Please check configuration.' });
        }

        res.status(200).json({ message: 'OTP sent to email', requireOtp: true, email: email });
    } catch (error) {
        console.error('Registration Error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Verify Register
app.post('/api/auth/verify-register', async (req, res) => {
    try {
        const { email, otp } = req.body;
        
        const otpRef = collection(db, 'otps');
        const q = query(otpRef, where("email", "==", email), where("type", "==", "signup"), where("otp", "==", otp));
        const querySnapshot = await getDocs(q);

        if (querySnapshot.empty) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        const otpDoc = querySnapshot.docs[0];
        const otpData = otpDoc.data();

        // Firestore stores dates as Timestamps, so we convert back to Date to compare
        const expiryDate = otpData.expiresAt.toDate ? otpData.expiresAt.toDate() : new Date(otpData.expiresAt);
        if (new Date() > expiryDate) {
            await deleteDoc(doc(db, 'otps', otpDoc.id));
            return res.status(400).json({ message: 'OTP expired' });
        }

        const newId = crypto.randomUUID();
        const newUser = {
            id: newId,
            name: otpData.signupData.name,
            email: otpData.signupData.email,
            password: otpData.signupData.password,
            role: otpData.signupData.role,
            createdAt: new Date().toISOString()
        };

        await setDoc(doc(db, 'users', newId), newUser);
        await deleteDoc(doc(db, 'otps', otpDoc.id));

        const payload = { user: { id: newId, role: newUser.role } };

        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' }, (err, token) => {
            if (err) throw err;
            res.status(201).json({ message: 'User registered successfully', token, role: newUser.role });
        });
    } catch (error) {
        console.error('Verify Registration Error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const usersRef = collection(db, 'users');
        const q = query(usersRef, where("email", "==", email));
        const querySnapshot = await getDocs(q);

        if (querySnapshot.empty) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const userDoc = querySnapshot.docs[0];
        const user = userDoc.data();

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpRef = collection(db, 'otps');
        
        await addDoc(otpRef, {
            email: email,
            otp: otp,
            type: 'login',
            userId: user.id,
            role: user.role,
            expiresAt: new Date(Date.now() + 10 * 60000) // 10 minutes
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Medisync - Login Verification OTP',
            html: generateOtpEmailHtml(otp)
        };

        try {
            await transporter.sendMail(mailOptions);
        } catch (mailError) {
            console.error("Mail error:", mailError.message);
            return res.status(500).json({ message: 'Failed to send OTP email. Please check configuration.' });
        }

        res.status(200).json({ message: 'OTP sent to email', requireOtp: true, email: email, role: user.role });
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Verify Login
app.post('/api/auth/verify-login', async (req, res) => {
    try {
        const { email, otp } = req.body;
        
        const otpRef = collection(db, 'otps');
        const q = query(otpRef, where("email", "==", email), where("type", "==", "login"), where("otp", "==", otp));
        const querySnapshot = await getDocs(q);

        if (querySnapshot.empty) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        const otpDoc = querySnapshot.docs[0];
        const otpData = otpDoc.data();

        const expiryDate = otpData.expiresAt.toDate ? otpData.expiresAt.toDate() : new Date(otpData.expiresAt);
        if (new Date() > expiryDate) {
            await deleteDoc(doc(db, 'otps', otpDoc.id));
            return res.status(400).json({ message: 'OTP expired' });
        }

        const payload = { user: { id: otpData.userId, role: otpData.role } };

        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' }, async (err, token) => {
            if (err) throw err;
            await deleteDoc(doc(db, 'otps', otpDoc.id));
            res.json({ token, role: otpData.role });
        });
    } catch (error) {
        console.error('Verify Login Error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Current User Profile
app.get('/api/users/me', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

        const splitToken = token.replace('Bearer ', '');
        const decoded = jwt.verify(splitToken, process.env.JWT_SECRET);

        const userDocRef = doc(db, 'users', decoded.user.id);
        const userSnap = await getDoc(userDocRef);

        if (!userSnap.exists()) return res.status(404).json({ message: 'User not found' });
        const user = userSnap.data();

        // Remove password before sending
        const userProfile = {
            id: user.id, name: user.name, email: user.email,
            phone: user.phone || '', gender: user.gender || '', age: user.age || '',
            role: user.role, allergies: user.allergies || '',
            disability: user.disability || [], diabetes: user.diabetes || null,
            diseases: user.diseases || [], createdAt: user.createdAt,
            doctorVerification: user.doctorVerification || null,
            // Doctor-specific fields
            experience: user.experience || '', hospital: user.hospital || '',
            specialty: user.specialty || '', fees: user.fees || '',
            about: user.about || '',
            profilePhoto: user.profilePhoto || null,
            otherCondition: user.otherCondition || ''
        };
        res.json(userProfile);
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid' });
    }
});

// Update User Profile
app.put('/api/users/me', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

        const splitToken = token.replace('Bearer ', '');
        const decoded = jwt.verify(splitToken, process.env.JWT_SECRET);

        const userDocRef = doc(db, 'users', decoded.user.id);
        const userSnap = await getDoc(userDocRef);

        if (!userSnap.exists()) return res.status(404).json({ message: 'User not found' });

        const updates = {};
        const allowedUpdateFields = ['name', 'phone', 'gender', 'age', 'allergies', 'disability', 'diabetes', 'diseases', 'experience', 'hospital', 'specialty', 'fees', 'about', 'profilePhoto', 'otherCondition'];
        
        for (const field of allowedUpdateFields) {
            if (req.body[field] !== undefined) {
                updates[field] = req.body[field];
            }
        }

        await updateDoc(userDocRef, updates);

        const updatedSnap = await getDoc(userDocRef);
        const user = updatedSnap.data();
        
        res.json({
            id: user.id, name: user.name, email: user.email,
            phone: user.phone || '', gender: user.gender || '', age: user.age || '',
            role: user.role, allergies: user.allergies || '',
            disability: user.disability || [], diabetes: user.diabetes || null,
            diseases: user.diseases || [],
            experience: user.experience || '', hospital: user.hospital || '',
            specialty: user.specialty || '', fees: user.fees || '',
            about: user.about || '',
            profilePhoto: user.profilePhoto || null,
            otherCondition: user.otherCondition || ''
        });
    } catch (error) {
        console.error('Profile Update Error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Doctor Verification Submission
app.post('/api/doctor/verify', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

        const splitToken = token.replace('Bearer ', '');
        const decoded = jwt.verify(splitToken, process.env.JWT_SECRET);

        const userDocRef = doc(db, 'users', decoded.user.id);
        const userSnap = await getDoc(userDocRef);

        if (!userSnap.exists()) return res.status(404).json({ message: 'User not found' });
        const user = userSnap.data();
        if (user.role !== 'Doctor') return res.status(403).json({ message: 'Only doctors can submit verification' });

        const { doctorName, registrationNumber, yearOfRegistration, stateMedicalCouncil } = req.body;

        if (!doctorName || !registrationNumber || !yearOfRegistration || !stateMedicalCouncil) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        await updateDoc(userDocRef, {
            doctorVerification: {
                doctorName,
                registrationNumber,
                yearOfRegistration,
                stateMedicalCouncil,
                status: 'pending',
                submittedAt: new Date().toISOString()
            }
        });

        res.json({ message: 'Verification request submitted successfully. Awaiting admin approval.', status: 'pending' });
    } catch (error) {
        console.error('Doctor Verification Error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get All Patients (for Doctor Dashboard)
app.get('/api/patients', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

        const splitToken = token.replace('Bearer ', '');
        const decoded = jwt.verify(splitToken, process.env.JWT_SECRET);

        const userDocRef = doc(db, 'users', decoded.user.id);
        const userSnap = await getDoc(userDocRef);
        
        if (!userSnap.exists() || userSnap.data().role !== 'Doctor') {
            return res.status(403).json({ message: 'Access denied. Doctors only.' });
        }

        const patientsRef = collection(db, 'users');
        const q = query(patientsRef, where("role", "==", "Patient"));
        const snapshot = await getDocs(q);

        const patients = snapshot.docs.map(docSnap => {
            const u = docSnap.data();
            return {
                id: u.id, name: u.name, email: u.email, phone: u.phone || '',
                gender: u.gender || '', age: u.age || '', allergies: u.allergies || '',
                disability: u.disability || [], diabetes: u.diabetes || null,
                diseases: u.diseases || [], createdAt: u.createdAt
            };
        });

        res.json(patients);
    } catch (error) {
        console.error('Patients Fetch Error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get All Verified Doctors (for Patient Dashboard "Consult Doctors")
app.get('/api/doctors', async (req, res) => {
    try {
        const doctorsRef = collection(db, 'users');
        const q = query(doctorsRef, where("role", "==", "Doctor"));
        const snapshot = await getDocs(q);

        const doctors = [];
        snapshot.forEach(docSnap => {
            const u = docSnap.data();
            if (u.doctorVerification && u.doctorVerification.status === 'verified') {
                doctors.push({
                    id: u.id,
                    name: u.doctorVerification.doctorName || u.name,
                    email: u.email,
                    gender: u.gender || '',
                    specialty: u.specialty || 'General Physician',
                    experience: u.experience || '',
                    hospital: u.hospital || '',
                    fees: u.fees || '',
                    about: u.about || '',
                    phone: u.phone || ''
                });
            }
        });
        
        res.json(doctors);
    } catch (error) {
        console.error('Doctors Fetch Error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ==== MEDICAL RECORDS ====
app.post('/api/records', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token' });
        const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        
        const { title, category, fileUrl, aiSummary, date } = req.body;
        const newRecord = {
            id: crypto.randomUUID(),
            userId: decoded.user.id,
            title, category, fileUrl, aiSummary, date,
            createdAt: new Date().toISOString()
        };
        await setDoc(doc(db, 'records', newRecord.id), newRecord);
        res.status(201).json({ message: 'Record saved', record: newRecord });
    } catch (e) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/records', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token' });
        const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        
        const recordsRef = collection(db, 'records');
        const q = query(recordsRef, where("userId", "==", decoded.user.id));
        const snapshot = await getDocs(q);
        const records = snapshot.docs.map(d => d.data());
        // Sort newest first
        records.sort((a,b) => new Date(b.date) - new Date(a.date));
        res.json(records);
    } catch (e) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ==== ACTIVE PRESCRIPTIONS ====
app.post('/api/prescriptions', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token' });
        const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        
        const { name, description, intakeTime, refillDays, backPhotoUrl } = req.body;
        const newPrescription = {
            id: crypto.randomUUID(),
            userId: decoded.user.id,
            name, description, intakeTime, refillDays, backPhotoUrl,
            status: 'Active',
            createdAt: new Date().toISOString()
        };
        await setDoc(doc(db, 'prescriptions', newPrescription.id), newPrescription);
        res.status(201).json({ message: 'Prescription added', prescription: newPrescription });
    } catch (e) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/prescriptions', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token' });
        const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        
        const pRef = collection(db, 'prescriptions');
        const q = query(pRef, where("userId", "==", decoded.user.id));
        const snapshot = await getDocs(q);
        const records = snapshot.docs.map(d => d.data());
        res.json(records);
    } catch (e) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ==== FAMILY MEMBERS ====
app.post('/api/family', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token' });
        const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        
        const userDocRef = doc(db, 'users', decoded.user.id);
        const userSnap = await getDoc(userDocRef);
        const primaryUser = userSnap.data();

        const { name, relation, dob, phone, email, gender } = req.body;
        
        const newMember = {
            id: crypto.randomUUID(),
            primaryUserId: decoded.user.id,
            name, relation, dob, phone, email, gender,
            status: 'Pending Verification',
            createdAt: new Date().toISOString()
        };
        await setDoc(doc(db, 'familyMembers', newMember.id), newMember);

        // Send invite email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Medisync - Family Account Invitation',
            html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; padding: 20px;">
                <img src="https://medisync-blue.vercel.app/email-logo.png" alt="Medisync Logo" style="max-height: 60px; margin-bottom: 25px;">
                <h2 style="color: #0f172a;">Hello ${name},</h2>
                <p><strong>${primaryUser.name}</strong> has invited you to join their Medisync family network.</p>
                <p>By creating your account, you will instantly connect your medical profile with theirs, allowing for seamless appointment booking and health tracking.</p>
                <div style="margin: 30px 0;">
                    <a href="https://smartmedisync.vercel.app/signup.html?email=${encodeURIComponent(email)}&name=${encodeURIComponent(name)}" style="background-color: #10b981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: bold;">Create Linked Account</a>
                </div>
            </div>`
        };
        try {
            await transporter.sendMail(mailOptions);
        } catch(err) {
            console.error("Family Mail error:", err);
        }

        res.status(201).json({ message: 'Family member added and invite sent', member: newMember });
    } catch (e) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/family', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token' });
        const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        
        const fRef = collection(db, 'familyMembers');
        const q = query(fRef, where("primaryUserId", "==", decoded.user.id));
        const snapshot = await getDocs(q);
        const members = snapshot.docs.map(d => d.data());
        res.json(members);
    } catch (e) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ==== AI RECORD ANALYZER ====
app.post('/api/analyze-record', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token' });
        
        const { fileBase64, mimeType } = req.body;
        if (!fileBase64 || !mimeType) return res.status(400).json({ message: 'Missing file data' });

        const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
        const response = await ai.models.generateContent({
            model: 'gemini-2.5-flash',
            contents: [
                { text: 'You are an advanced medical systems AI. Review this uploaded medical document (lab report, imaging note, etc). Provide a concise plain-text summary (do not use markdown formatting like asterisks or bolding, just use newlines and dashes). Highlight any critical anomalies, key findings, and action items.' },
                { inlineData: { data: fileBase64.split(',')[1] || fileBase64, mimeType: mimeType } }
            ]
        });

        res.json({ aiSummary: response.text });
    } catch (error) {
        console.error('Analyze Record Error:', error);
        res.status(500).json({ message: 'AI Analysis failed', aiSummary: 'AI Analysis currently unavailable. The report was uploaded successfully.' });
    }
});

// Chatbot AI Endpoint
app.post('/api/chat', async (req, res) => {
    try {
        const { message, role } = req.body;
        if (!message) return res.status(400).json({ error: "Message is required" });

        let systemPrompt = "";
        if (role === "Doctor") {
            systemPrompt = `You are 'Medisync Pro', a highly specialized and advanced AI medical assistant built strictly for licensed doctors and medical professionals.
INSTRUCTIONS:
1. Maintain an extremely clinical, professional, data-centric, and concise tone.
2. Use medical terminology confidently. Analyze symptoms, highlight critical risk factors, and provide differential diagnosis brainstorming when asked.
3. Be direct. Do not use conversational filler.
4. IMPORTANT FORMATTING: Do NOT use markdown. Do not use asterisks (*) for bolding or italics. Use simple dashes (-) for lists and use line breaks for readability. Output clean plain text.`;
        } else {
            systemPrompt = `You are 'Medisync AI', a warm, empathetic, and clear intelligent medical assistant for patients.
INSTRUCTIONS:
1. Use simple language. Avoid complex medical jargon, but remain highly informative.
2. Provide triage analysis, symptom checking, and general hygiene tips. Be reassuring and friendly.
3. SAFETY CONSTRAINT: Always remind the patient to consult a doctor for severe symptoms. Do not diagnose explicitly.
4. IMPORTANT FORMATTING: Do NOT use markdown. Do not use asterisks (*) for bolding or italics. Use simple dashes (-) for lists and use double line breaks for spacing out paragraphs. Output clean plain text.`;
        }

        let envKey = process.env.GROQ_API_KEY;
        const apiKey = envKey;
        
        // Context Injection
        let userContext = "";
        const token = req.header('Authorization');
        if (token) {
            try {
                const splitToken = token.replace('Bearer ', '');
                const decoded = jwt.verify(splitToken, process.env.JWT_SECRET);
                const recordsRef = collection(db, 'records');
                const q = query(recordsRef, where("userId", "==", decoded.user.id));
                const snapshot = await getDocs(q);
                if (!snapshot.empty) {
                    userContext = "\nThe patient has the following medical records available:\n";
                    snapshot.forEach(doc => {
                        const rec = doc.data();
                        userContext += `- Title: "${rec.title}" (Date: ${rec.date})\n  AI Summary: ${rec.aiSummary || 'Not available.'}\n\n`;
                    });
                    userContext += "If the patient asks about their records or reports, use the above summaries to answer accurately.\n";
                }
            } catch(e) { }
        }

        const aiResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: "llama-3.3-70b-versatile",
                messages: [
                    { role: "system", content: systemPrompt + (userContext ? "\n" + userContext : "") },
                    { role: "user", content: message }
                ]
            })
        });

        if (!aiResponse.ok) {
            const errorText = await aiResponse.text();
            console.error("Groq API error:", errorText);
            return res.status(500).json({ reply: "I am currently unable to process your request." });
        }

        const data = await aiResponse.json();
        res.json({ reply: data.choices[0]?.message?.content || "No response generated." });
    } catch (error) {
        console.error("Chat API Error:", error);
        res.status(500).json({ reply: "I am experiencing network issues connecting to the Medisync Neural Network. Please ensure your API Key is valid or try again later." });
    }
});

// ===== ADMIN ROUTES =====

// Admin Login
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const token = jwt.sign({ admin: true }, process.env.JWT_SECRET, { expiresIn: '7d' });
        return res.json({ token });
    }
    res.status(401).json({ message: 'Invalid admin credentials' });
});

// Admin middleware
function adminAuth(req, res, next) {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ message: 'No token' });
    try {
        const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        if (!decoded.admin) return res.status(403).json({ message: 'Not admin' });
        next();
    } catch (e) {
        res.status(401).json({ message: 'Invalid token' });
    }
}

// Get all users (admin)
app.get('/api/admin/users', adminAuth, async (req, res) => {
    try {
        const snapshot = await getDocs(collection(db, 'users'));
        const safeUsers = snapshot.docs.map(docSnap => {
            const u = docSnap.data();
            return {
                id: u.id, name: u.name, email: u.email, role: u.role,
                phone: u.phone || '', gender: u.gender || '', age: u.age || '',
                specialty: u.specialty || '', experience: u.experience || '',
                hospital: u.hospital || '', fees: u.fees || '', about: u.about || '',
                allergies: u.allergies || '', disability: u.disability || [],
                diabetes: u.diabetes || null, diseases: u.diseases || [],
                createdAt: u.createdAt, doctorVerification: u.doctorVerification || null
            };
        });
        res.json(safeUsers);
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin verify/reject doctor
app.put('/api/admin/verify-doctor/:userId', adminAuth, async (req, res) => {
    try {
        const { status } = req.body;
        const userDocRef = doc(db, 'users', req.params.userId);
        const userSnap = await getDoc(userDocRef);
        
        if (!userSnap.exists()) return res.status(404).json({ message: 'User not found' });
        const user = userSnap.data();
        if (!user.doctorVerification) return res.status(400).json({ message: 'No verification request' });
        
        await updateDoc(userDocRef, {
            'doctorVerification.status': status
        });

        res.json({ message: `Doctor ${status} successfully` });
    } catch (error) {
        console.error('Admin verify error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get all appointments (admin)
app.get('/api/admin/appointments', adminAuth, async (req, res) => {
    try {
        const snapshot = await getDocs(collection(db, 'appointments'));
        const appointments = snapshot.docs.map(d => d.data());
        res.json(appointments);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ===== APPOINTMENT BOOKING =====
app.post('/api/appointments', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token' });
        const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        
        const userDocRef = doc(db, 'users', decoded.user.id);
        const userSnap = await getDoc(userDocRef);
        if (!userSnap.exists()) return res.status(404).json({ message: 'User not found' });
        const user = userSnap.data();

        const { doctorName, doctorSpecialty, problem, date, time } = req.body;
        const newApptId = crypto.randomUUID();
        const appointment = {
            id: newApptId,
            patientId: user.id,
            patientName: user.name,
            patientEmail: user.email,
            doctorName, doctorSpecialty, problem, date, time,
            status: 'Scheduled',
            createdAt: new Date().toISOString()
        };

        const apptRef = doc(db, 'appointments', newApptId);
        await setDoc(apptRef, appointment);

        res.status(201).json({ message: 'Appointment booked successfully', appointment });
    } catch (error) {
        console.error('Appointment booking error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get user appointments
app.get('/api/appointments', async (req, res) => {
    try {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'No token' });
        const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        
        const apptRef = collection(db, 'appointments');
        const q = query(apptRef, where("patientId", "==", decoded.user.id));
        const snapshot = await getDocs(q);

        const userAppts = snapshot.docs.map(d => d.data());
        res.json(userAppts);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Seed Default Doctor
async function seedDefaultDoctor() {
    try {
        const usersRef = collection(db, 'users');
        const q = query(usersRef, where("email", "==", DEFAULT_DOCTOR_EMAIL));
        const snapshot = await getDocs(q);

        if (!snapshot.empty) return;

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(DEFAULT_DOCTOR_PASS, salt);
        const newId = crypto.randomUUID();

        const defaultDoc = {
            id: newId,
            name: 'Dr. Medisync',
            email: DEFAULT_DOCTOR_EMAIL,
            password: hashedPassword,
            role: 'Doctor',
            gender: 'Male',
            phone: '9876543210',
            specialty: 'General Physician',
            experience: '10+ years',
            hospital: 'Medisync Central Hospital',
            fees: '500',
            about: 'Experienced general physician specializing in preventive care and chronic disease management.',
            createdAt: new Date().toISOString(),
            doctorVerification: {
                doctorName: 'Dr. Medisync',
                registrationNumber: 'MCI-DEFAULT-001',
                yearOfRegistration: '2016',
                stateMedicalCouncil: 'Medical Council of India',
                status: 'verified',
                submittedAt: new Date().toISOString()
            }
        };

        await setDoc(doc(db, 'users', newId), defaultDoc);
        console.log('Default doctor seeded: testdoc@gmail.com / Doc@4321');
    } catch (error) {
        console.error('Error seeding default doctor:', error);
    }
}

// Start Server
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, async () => {
        await seedDefaultDoctor();
        console.log(`Server is running on port ${PORT}`);
    });
} else {
    // Ensure seeding still happens on serverless spin-up
    // seedDefaultDoctor().catch(console.error); // Disabled to prevent duplicate doctor race conditions
}

module.exports = app;
