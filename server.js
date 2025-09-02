// MultipleFiles/server.js - Corrected and Rewritten

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');

const app = express();

// ===================== Constants =====================
const ROLES = {
  STUDENT: 'student',
  FACULTY: 'faculty',
  ADMIN: 'admin'
};

const PROJECT_STATUS = {
  OPEN: 'open',
  PENDING_APPROVAL: 'pending_approval',
  ONGOING: 'ongoing',
  SUBMITTED: 'submitted',
  COMPLETED: 'completed',
  REJECTED: 'rejected'
};

const SUBMISSION_STATUS = {
  PENDING_REVIEW: 'pending_review',
  REVIEWED: 'reviewed'
};

const PROJECT_VISIBILITY = {
  PUBLIC: 'public',
  PRIVATE: 'private'
};

// ===================== Basic Middleware =====================
const origins = (process.env.CORS_ORIGINS || 'http://127.0.0.1:5500,http://localhost:5500')
  .split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: origins.length ? origins : true }));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files (CSS, JS, images) but do not auto-serve index.html
app.use(express.static(path.join(__dirname, 'public'), { index: false }));
// Serve files from root directory (assets), but do not auto-serve index.html
app.use(express.static(__dirname, { index: false }));
// Serve index.html for root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ===================== Upload Config =====================
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || './uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
app.use('/uploads', express.static(UPLOAD_DIR)); // Serve uploaded files

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.random().toString(36).slice(2, 8);
    cb(null, `${unique}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// ===================== MongoDB Connection =====================
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/protrack';
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1); // Exit process if DB connection fails
  });

// ===================== Schemas & Models =====================
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, index: true, required: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: Object.values(ROLES), default: ROLES.STUDENT },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const projectSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  faculty_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  student_ids: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  status: { type: String, enum: Object.values(PROJECT_STATUS), default: PROJECT_STATUS.OPEN },
  deadline: { type: Date, default: null },
  tags: [String],
  visibility: { type: String, enum: Object.values(PROJECT_VISIBILITY), default: PROJECT_VISIBILITY.PRIVATE },
  team_size: { type: Number, default: 1, min: 1 },
  created_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  creator_role: { type: String, enum: Object.values(ROLES), required: true },
  resources: [{ name: String, url: String }],
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date, default: null } // Added for accurate completion history
});
const Project = mongoose.model('Project', projectSchema);

const submissionSchema = new mongoose.Schema({
  project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  student_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  note: String,
  files: [String], // Stores relative paths
  grade: { type: Number, default: null, min: 0, max: 100 },
  feedback: String,
  status: { type: String, enum: Object.values(SUBMISSION_STATUS), default: SUBMISSION_STATUS.PENDING_REVIEW },
  createdAt: { type: Date, default: Date.now }
});
const Submission = mongoose.model('Submission', submissionSchema);

const messageSchema = new mongoose.Schema({
  sender_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipient_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  subject: { type: String, required: true },
  body: { type: String, required: true },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

const commentSchema = new mongoose.Schema({
  project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  comment_text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const Comment = mongoose.model('Comment', commentSchema);

// ===================== Auth Helpers =====================
const JWT_SECRET = process.env.JWT_SECRET; // MUST be set in .env
if (!JWT_SECRET) {
  console.error('FATAL ERROR: JWT_SECRET is not defined in environment variables.');
  process.exit(1);
}
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '7d';

function signToken(user) {
  const payload = { id: user._id.toString(), name: user.name, sub: user.email, role: user.role };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) {
    return res.status(401).json({ detail: 'Authentication required: Missing or malformed token' });
  }
  const token = h.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // Attach user payload to request
    next();
  } catch (e) {
    console.error('JWT verification failed:', e.message);
    return res.status(401).json({ detail: 'Invalid or expired token' });
  }
}

// Role-based authorization middleware
function roleMiddleware(roles = []) {
  if (typeof roles === 'string') {
    roles = [roles];
  }
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ detail: 'Access denied: User role not found' });
    }
    if (roles.length && !roles.includes(req.user.role)) {
      return res.status(403).json({ detail: `Access denied: Requires one of roles: ${roles.join(', ')}` });
    }
    next();
  };
}

// --- Utility Functions for Data Population ---
// These are kept for specific single-item population where direct populate() might be complex
// For lists, direct populate in query is preferred for performance.

async function populateProjectDetails(project) {
  if (!project) return null;
  const populatedProject = project.toObject ? project.toObject() : { ...project }; // Ensure it's a plain object

  if (populatedProject.faculty_id) {
    const faculty = await User.findById(populatedProject.faculty_id).select('name').lean();
    populatedProject.faculty_name = faculty ? faculty.name : 'N/A';
  } else {
    populatedProject.faculty_name = 'Unassigned Faculty';
  }

  if (populatedProject.student_ids && populatedProject.student_ids.length > 0) {
    const students = await User.find({ _id: { $in: populatedProject.student_ids } }).select('name').lean();
    populatedProject.student_names = students.map(s => s.name);
    populatedProject.student_name = students.length > 0 ? students[0].name : 'N/A'; // For single student display
  } else {
    populatedProject.student_names = [];
    populatedProject.student_name = 'Unassigned';
  }

  if (populatedProject.created_by) {
    const creator = await User.findById(populatedProject.created_by).select('name role').lean();
    populatedProject.creator_name = creator ? creator.name : 'N/A';
    // populatedProject.creator_role is already in schema, no need to overwrite
  } else {
    populatedProject.creator_name = 'N/A';
  }

  // Ensure resources have full URLs
  if (populatedProject.resources && populatedProject.resources.length > 0) {
    populatedProject.resources = populatedProject.resources.map(res => ({
      name: res.name,
      url: res.url.startsWith('http') ? res.url : `${process.env.BASE_URL || 'http://localhost:8000'}/${res.url}`
    }));
  }

  return populatedProject;
}

async function populateSubmissionDetails(submission) {
  if (!submission) return null;
  const populatedSubmission = submission.toObject ? submission.toObject() : { ...submission };

  if (populatedSubmission.project_id) {
    const project = await Project.findById(populatedSubmission.project_id).select('title').lean();
    populatedSubmission.project_title = project ? project.title : 'N/A';
  }

  if (populatedSubmission.student_id) {
    const student = await User.findById(populatedSubmission.student_id).select('name').lean();
    populatedSubmission.student_name = student ? student.name : 'N/A';
  }

  // Ensure files have full URLs
  if (populatedSubmission.files && populatedSubmission.files.length > 0) {
    populatedSubmission.file_paths = populatedSubmission.files.map(filePath => ({
      name: path.basename(filePath),
      url: `${process.env.BASE_URL || 'http://localhost:8000'}/${filePath}`
    }));
  } else {
    populatedSubmission.file_paths = [];
  }

  return populatedSubmission;
}

async function populateMessageDetails(message) {
  if (!message) return null;
  const populatedMessage = message.toObject ? message.toObject() : { ...message };

  if (populatedMessage.sender_id) {
    const sender = await User.findById(populatedMessage.sender_id).select('name').lean();
    populatedMessage.sender_name = sender ? sender.name : 'N/A';
  }
  if (populatedMessage.recipient_id) {
    const recipient = await User.findById(populatedMessage.recipient_id).select('name').lean();
    populatedMessage.recipient_name = recipient ? recipient.name : 'N/A';
  }
  return populatedMessage;
}

async function populateCommentDetails(comment) {
  if (!comment) return null;
  const populatedComment = comment.toObject ? comment.toObject() : { ...comment };

  if (populatedComment.user_id) {
    const user = await User.findById(populatedComment.user_id).select('name').lean();
    populatedComment.user_name = user ? user.name : 'N/A';
  }
  return populatedComment;
}


// --- Routes ---

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Register
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ detail: 'Name, email, and password are required.' });
    }
    if (role && ![ROLES.STUDENT, ROLES.FACULTY, ROLES.ADMIN].includes(role)) {
      return res.status(400).json({ detail: 'Invalid role specified.' });
    }

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ detail: 'Email already registered.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email: email.toLowerCase(), passwordHash, role: role || ROLES.STUDENT });
    return res.status(201).json({ id: user._id.toString(), name: user.name, email: user.email, role: user.role });
  } catch (err) {
    console.error('Registration error:', err);
    return res.status(500).json({ detail: 'Registration failed due to an internal server error.' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const username = req.body.username || req.body.email;
    const password = req.body.password;
    if (!username || !password) {
      return res.status(400).json({ detail: 'Email and password are required.' });
    }

    const user = await User.findOne({ email: username.toLowerCase() });
    if (!user) {
      return res.status(401).json({ detail: 'Invalid credentials.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ detail: 'Invalid credentials.' });
    }

    const access_token = signToken(user);
    return res.json({ access_token, token_type: 'bearer', user_role: user.role, user_id: user._id.toString() });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ detail: 'Login failed due to an internal server error.' });
  }
});

// List users (Admin/Faculty only, or self for students)
app.get('/users', authMiddleware, roleMiddleware([ROLES.ADMIN, ROLES.FACULTY, ROLES.STUDENT]), async (req, res) => {
  try {
    const query = {};
    const requestingUserRole = req.user.role;
    const requestingUserId = new mongoose.Types.ObjectId(req.user.id);

    if (req.query.role) {
      if (!Object.values(ROLES).includes(req.query.role)) {
        return res.status(400).json({ detail: 'Invalid role filter.' });
      }
      query.role = req.query.role;
    }

    if (req.query.search) {
      query.name = { $regex: req.query.search, $options: 'i' };
    }

    // Authorization logic for listing users
    if (requestingUserRole === ROLES.STUDENT) {
      // Students can see faculty members (for project proposals) or their own profile
      if (query.role === ROLES.FACULTY) {
        // Allow students to see all faculty members for project proposals
        // No additional filtering needed
      } else if (req.query.id && req.query.id === requestingUserId.toString()) {
        query._id = requestingUserId;
      } else {
        return res.status(403).json({ detail: 'Students can only view faculty members or their own profile.' });
      }
    } else if (requestingUserRole === ROLES.FACULTY) {
      // Faculty can see all students and other faculty, but not admins.
      // If a faculty requests students, they should only see students assigned to their projects.
      if (query.role === ROLES.STUDENT) {
        const facultyProjects = await Project.find({ faculty_id: requestingUserId }).select('student_ids').lean();
        const assignedStudentIds = new Set();
        facultyProjects.forEach(p => p.student_ids.forEach(id => assignedStudentIds.add(id.toString())));
        query._id = { $in: Array.from(assignedStudentIds).map(id => new mongoose.Types.ObjectId(id)) };
      } else if (query.role === ROLES.FACULTY || !query.role) {
        // Faculty can see other faculty or all users except admins
        query.role = { $ne: ROLES.ADMIN };
      }
    }
    // Admins can see all users based on query filters.

    let users = await User.find(query, { passwordHash: 0 }).lean();

    const usersWithStats = await Promise.all(users.map(async (u) => {
      const userObj = { id: u._id.toString(), name: u.name, email: u.email, role: u.role };
      if (u.role === ROLES.STUDENT) {
        const studentProjects = await Project.find({ student_ids: u._id }).lean();
        userObj.project_count = studentProjects.length;

        const studentSubmissions = await Submission.find({ student_id: u._id }).lean();
        const grades = studentSubmissions.filter(s => typeof s.grade === 'number').map(s => s.grade);
        userObj.avg_grade = grades.length ? parseFloat((grades.reduce((a, b) => a + b, 0) / grades.length).toFixed(2)) : 'N/A';

        const completedOnTime = studentProjects.filter(p => p.status === PROJECT_STATUS.COMPLETED && p.deadline && p.completedAt && p.completedAt <= p.deadline).length;
        userObj.on_time_percentage = studentProjects.length > 0 ? ((completedOnTime / studentProjects.length) * 100).toFixed(0) : 'N/A';
      }
      return userObj;
    }));

    res.json(usersWithStats);
  } catch (err) {
    console.error('Failed to fetch users:', err);
    return res.status(500).json({ detail: 'Failed to fetch users due to an internal server error.' });
  }
});

// Delete project (Admin only)
app.delete('/projects/:id', authMiddleware, roleMiddleware([ROLES.ADMIN]), async (req, res) => {
  const projectId = req.params.id;
  if (!mongoose.Types.ObjectId.isValid(projectId)) {
    return res.status(400).json({ detail: 'Invalid project ID.' });
  }

  // Start a session for transaction
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Find the project to be deleted
    const project = await Project.findById(projectId).session(session);
    if (!project) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ detail: 'Project not found.' });
    }

    // Delete related data
    await Submission.deleteMany({ project_id: projectId }).session(session);
    await Comment.deleteMany({ project_id: projectId }).session(session);
    
    // Delete the project
    await Project.findByIdAndDelete(projectId).session(session);
    
    // Commit the transaction
    await session.commitTransaction();
    session.endSession();
    
    return res.json({ detail: 'Project and all related data deleted successfully.' });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('Error deleting project:', error);
    return res.status(500).json({ detail: 'An error occurred while deleting the project.' });
  }
});

// Delete user (Admin only)
app.delete('/users/:id', authMiddleware, roleMiddleware([ROLES.ADMIN]), async (req, res) => {
  try {
    const userId = req.params.id;
    console.log('Delete request for user ID:', userId);
    
    if (!userId || userId.trim() === '') {
      return res.status(400).json({ detail: 'User ID is required.' });
    }
    
    // Validate ObjectId format
    let objectId;
    try {
      objectId = new mongoose.Types.ObjectId(userId);
    } catch (error) {
      console.log('Invalid ObjectId format:', userId, error.message);
      return res.status(400).json({ detail: 'Invalid user ID format.' });
    }

    // Prevent self-deletion
    if (userId === req.user.id) {
      return res.status(400).json({ detail: 'You cannot delete your own account.' });
    }

    // Find the user to be deleted
    const userToDelete = await User.findById(userId);
    if (!userToDelete) {
      return res.status(404).json({ detail: 'User not found.' });
    }

    // Delete user and related data (simple operations for standalone MongoDB)
    // Delete user's projects if they are the creator
    await Project.deleteMany({ created_by: userId });
    
    // Remove user from project student_ids and faculty_id
    await Project.updateMany(
      { $or: [{ student_ids: userId }, { faculty_id: userId }] },
      { 
        $pull: { student_ids: userId },
        $unset: { faculty_id: "" }
      }
    );

    // Delete user's submissions
    await Submission.deleteMany({ student_id: userId });
    
    // Finally, delete the user
    await User.findByIdAndDelete(userId);
    
    return res.json({ detail: 'User and all related data deleted successfully.' });
  } catch (error) {
    console.error('Error deleting user:', error);
    return res.status(500).json({ 
      detail: error.message || 'Failed to delete user due to an internal server error.' 
    });
  }
});

// Student profile used by frontend modal (accessible by faculty/admin for any student, or by student for self)
app.get('/students/:id', authMiddleware, async (req, res) => {
  try {
    const studentId = new mongoose.Types.ObjectId(req.params.id);
    const requestingUserId = new mongoose.Types.ObjectId(req.user.id);
    const requestingUserRole = req.user.role;

    const student = await User.findById(studentId).lean();
    if (!student || student.role !== ROLES.STUDENT) {
      return res.status(404).json({ detail: 'Student not found.' });
    }

    // Authorization: Student can only view their own profile. Faculty/Admin can view any student profile.
    if (requestingUserRole === ROLES.STUDENT && studentId.toString() !== requestingUserId.toString()) {
      return res.status(403).json({ detail: 'Access denied: Students can only view their own profile.' });
    }

    const projects = await Project.find({ student_ids: studentId }).sort({ createdAt: -1 }).lean();
    const projects_count = projects.length;

    const subs = await Submission.find({ student_id: studentId }).sort({ createdAt: 1 }).lean();
    const grades = subs.filter(s => typeof s.grade === 'number').map(s => s.grade);
    const avg_grade = grades.length ? parseFloat((grades.reduce((a, b) => a + b, 0) / grades.length).toFixed(2)) : null;

    const performance = subs.slice(-6).map((s) => ({
      label: (s.createdAt || new Date()).toISOString().slice(0, 10),
      value: s.grade ?? 0
    }));

    const recent_projects = projects.slice(0, 5).map(p => ({ id: p._id.toString(), title: p.title, description: p.description }));

    return res.json({
      username: student.name,
      projects_count,
      avg_grade,
      performance,
      recent_projects
    });
  } catch (err) {
    console.error('Failed to load student profile:', err);
    return res.status(500).json({ detail: 'Failed to load student profile due to an internal server error.' });
  }
});

// Projects list & details with robust filtering
app.get('/projects', authMiddleware, async (req, res) => {
  try {
    const query = {};
    const requestingUserId = new mongoose.Types.ObjectId(req.user.id);
    const requestingUserRole = req.user.role;

    if (req.query.project_id) { // For fetching a single project by ID
      const project = await Project.findById(req.query.project_id).lean();
      if (!project) return res.status(404).json({ detail: 'Project not found.' });

      // Authorization for single project view
      const isFacultySupervisor = project.faculty_id && project.faculty_id.equals(requestingUserId);
      const isAssignedStudent = project.student_ids.some(id => id.equals(requestingUserId));
      const isPublic = project.visibility === PROJECT_VISIBILITY.PUBLIC;

      if (requestingUserRole === ROLES.ADMIN || isFacultySupervisor || isAssignedStudent || isPublic) {
        const populatedProject = await populateProjectDetails(project);
        return res.json([populatedProject]); // Return as array for frontend consistency
      } else {
        return res.status(403).json({ detail: 'Access denied: You are not authorized to view this project.' });
      }
    }

    // Build query based on user role and filters
    if (requestingUserRole === ROLES.STUDENT) {
      // Students can see projects assigned to them or public projects
      query.$or = [{ student_ids: requestingUserId }, { visibility: PROJECT_VISIBILITY.PUBLIC }];
    } else if (requestingUserRole === ROLES.FACULTY) {
      // Faculty can see projects they supervise or public projects
      query.$or = [{ faculty_id: requestingUserId }, { visibility: PROJECT_VISIBILITY.PUBLIC }];
    }
    // Admin can see all projects, no specific role-based query filter needed here.

    if (req.query.assigned_to) {
      // Ensure the assigned_to filter is only applied if the requesting user is authorized to see it
      if (requestingUserRole === ROLES.ADMIN || (requestingUserRole === ROLES.FACULTY && req.query.assigned_to === requestingUserId.toString())) {
        query.student_ids = new mongoose.Types.ObjectId(req.query.assigned_to);
      } else if (requestingUserRole === ROLES.STUDENT && req.query.assigned_to !== requestingUserId.toString()) {
        return res.status(403).json({ detail: 'Access denied: Students can only filter by their own assigned projects.' });
      }
    }
    if (req.query.faculty_id) {
      // Ensure the faculty_id filter is only applied if the requesting user is authorized to see it
      if (requestingUserRole === ROLES.ADMIN || (requestingUserRole === ROLES.STUDENT && req.query.faculty_id === requestingUserId.toString())) {
        query.faculty_id = new mongoose.Types.ObjectId(req.query.faculty_id);
      } else if (requestingUserRole === ROLES.FACULTY && req.query.faculty_id !== requestingUserId.toString()) {
        return res.status(403).json({ detail: 'Access denied: Faculty can only filter by their own supervised projects.' });
      }
    }

    if (req.query.status && req.query.status !== 'all') {
      const statuses = req.query.status.split(',');
      if (!statuses.every(s => Object.values(PROJECT_STATUS).includes(s))) {
        return res.status(400).json({ detail: 'Invalid project status filter.' });
      }
      query.status = { $in: statuses };
    }
    if (req.query.visibility) {
      if (!Object.values(PROJECT_VISIBILITY).includes(req.query.visibility)) {
        return res.status(400).json({ detail: 'Invalid project visibility filter.' });
      }
      query.visibility = req.query.visibility;
    }
    if (req.query.search) {
      query.$or = [
        { title: { $regex: req.query.search, $options: 'i' } },
        { description: { $regex: req.query.search, $options: 'i' } }
      ];
    }

    // For list view, use populate for efficiency
    const projects = await Project.find(query)
      .populate({ path: 'faculty_id', select: 'name' })
      .populate({ path: 'student_ids', select: 'name' })
      .populate({ path: 'created_by', select: 'name role' })
      .sort({ createdAt: -1 })
      .lean();

    const formattedProjects = projects.map(p => ({
      id: p._id.toString(),
      title: p.title,
      description: p.description,
      faculty_id: p.faculty_id ? p.faculty_id._id.toString() : null,
      faculty_name: p.faculty_id ? p.faculty_id.name : 'Unassigned Faculty',
      student_ids: p.student_ids.map(s => s._id.toString()),
      student_names: p.student_ids.map(s => s.name),
      student_name: p.student_ids.length > 0 ? p.student_ids[0].name : 'Unassigned', // For single student display
      status: p.status,
      deadline: p.deadline,
      visibility: p.visibility,
      team_size: p.team_size,
      created_by: p.created_by ? p.created_by._id.toString() : null,
      creator_name: p.created_by ? p.created_by.name : 'N/A',
      creator_role: p.creator_role,
      resources: p.resources.map(res => ({
        name: res.name,
        url: res.url.startsWith('http') ? res.url : `${process.env.BASE_URL || 'http://localhost:8000'}/${res.url}`
      })),
      createdAt: p.createdAt,
      completedAt: p.completedAt
    }));

    res.json(formattedProjects);
  } catch (err) {
    console.error('Failed to fetch projects:', err);
    return res.status(500).json({ detail: 'Failed to fetch projects due to an internal server error.' });
  }
});

app.get('/projects/:id', authMiddleware, async (req, res) => {
  try {
    const projectId = new mongoose.Types.ObjectId(req.params.id);
    const requestingUserId = new mongoose.Types.ObjectId(req.user.id);
    const requestingUserRole = req.user.role;

    const project = await Project.findById(projectId).lean();
    if (!project) return res.status(404).json({ detail: 'Project not found.' });

    // Authorization for single project view
    const isFacultySupervisor = project.faculty_id && project.faculty_id.equals(requestingUserId);
    const isAssignedStudent = project.student_ids.some(id => id.equals(requestingUserId));
    const isPublic = project.visibility === PROJECT_VISIBILITY.PUBLIC;

    if (requestingUserRole === ROLES.ADMIN || isFacultySupervisor || isAssignedStudent || isPublic) {
      const populatedProject = await populateProjectDetails(project); // Use utility for single item
      return res.json({
        id: populatedProject._id.toString(),
        title: populatedProject.title,
        description: populatedProject.description,
        faculty_id: populatedProject.faculty_id ? populatedProject.faculty_id.toString() : null,
        faculty_name: populatedProject.faculty_name,
        student_ids: populatedProject.student_ids.map(id => id.toString()),
        student_names: populatedProject.student_names,
        student_name: populatedProject.student_name,
        status: populatedProject.status,
        deadline: populatedProject.deadline,
        visibility: populatedProject.visibility,
        team_size: populatedProject.team_size,
        created_by: populatedProject.created_by ? populatedProject.created_by.toString() : null,
        creator_name: populatedProject.creator_name,
        creator_role: populatedProject.creator_role,
        resources: populatedProject.resources,
        createdAt: populatedProject.createdAt,
        completedAt: populatedProject.completedAt
      });
    } else {
      return res.status(403).json({ detail: 'Access denied: You are not authorized to view this project.' });
    }
  } catch (err) {
    console.error('Failed to fetch project:', err);
    return res.status(500).json({ detail: 'Failed to fetch project due to an internal server error.' });
  }
});

// Create project (faculty/admin) or proposal (student)
app.post('/projects', authMiddleware, async (req, res) => {
  try {
    const payload = req.body || {};
    const creatorRole = req.user.role;
    const creatorId = new mongoose.Types.ObjectId(req.user.id);

    let projectStatus = payload.status || PROJECT_STATUS.OPEN;
    let studentIds = [];
    if (payload.assigned_to) {
      if (Array.isArray(payload.assigned_to)) {
        studentIds = payload.assigned_to
          .filter(id => id && id.trim()) // Filter out empty/null values
          .map(id => new mongoose.Types.ObjectId(id));
      } else if (payload.assigned_to.trim()) {
        studentIds = [new mongoose.Types.ObjectId(payload.assigned_to)];
      }
    }
    let facultyId = payload.faculty_id ? new mongoose.Types.ObjectId(payload.faculty_id) : null;
    let visibility = payload.visibility || PROJECT_VISIBILITY.PRIVATE;
    let teamSize = payload.team_size || 1;
    let resources = payload.resources || [];

    if (!payload.title || !payload.description) {
      return res.status(400).json({ detail: 'Project title and description are required.' });
    }

    if (creatorRole === ROLES.STUDENT) {
      // Student proposing a project
      projectStatus = PROJECT_STATUS.PENDING_APPROVAL;
      studentIds = [creatorId]; // Student is automatically assigned to their proposal
      if (!facultyId) {
        return res.status(400).json({ detail: 'Faculty supervisor is required for student proposals.' });
      }
      visibility = PROJECT_VISIBILITY.PRIVATE; // Student proposals are always private initially
      teamSize = payload.team_size || 1; // Allow student to propose team size
    } else if ([ROLES.FACULTY, ROLES.ADMIN].includes(creatorRole)) {
      // Faculty/Admin creating a project
      if (visibility === PROJECT_VISIBILITY.PRIVATE && studentIds.length === 0) {
        return res.status(400).json({ detail: 'Private projects must be assigned to at least one student.' });
      }
      if (visibility === PROJECT_VISIBILITY.PUBLIC) {
        studentIds = []; // Public projects are not assigned initially
      }
      if (!facultyId && creatorRole === ROLES.FACULTY) {
        facultyId = creatorId; // Faculty assigns themselves if not specified
      }
    } else {
      return res.status(403).json({ detail: 'Unauthorized to create projects.' });
    }

    const doc = {
      title: payload.title,
      description: payload.description,
      faculty_id: facultyId,
      student_ids: studentIds,
      status: projectStatus,
      deadline: payload.deadline ? new Date(payload.deadline) : null,
      tags: payload.tags || [],
      visibility: visibility,
      team_size: teamSize,
      created_by: creatorId,
      creator_role: creatorRole,
      resources: resources
    };

    const p = await Project.create(doc);
    return res.status(201).json({ id: p._id.toString(), title: p.title, status: p.status, detail: 'Project created successfully.' });
  } catch (err) {
    console.error('Failed to create project:', err);
    return res.status(500).json({ detail: 'Failed to create project due to an internal server error.' });
  }
});

// Update project status (for faculty approval/rejection, or completion)
app.put('/projects/:id/status', authMiddleware, roleMiddleware([ROLES.FACULTY, ROLES.ADMIN]), async (req, res) => {
  try {
    const projectId = new mongoose.Types.ObjectId(req.params.id);
    const { status } = req.body;

    if (!status || !Object.values(PROJECT_STATUS).includes(status)) {
      return res.status(400).json({ detail: 'Invalid project status provided.' });
    }

    const project = await Project.findById(projectId);
    if (!project) return res.status(404).json({ detail: 'Project not found.' });

    // Authorization: Faculty can only update status for projects they supervise. Admin can update any.
    if (req.user.role === ROLES.FACULTY && project.faculty_id && project.faculty_id.toString() !== req.user.id) {
      return res.status(403).json({ detail: 'You are not authorized to update the status of this project.' });
    }

    // Specific logic for status transitions
    if (status === PROJECT_STATUS.COMPLETED && project.status !== PROJECT_STATUS.COMPLETED) {
      project.completedAt = new Date(); // Record completion date
    } else if (status !== PROJECT_STATUS.COMPLETED && project.completedAt) {
      project.completedAt = null; // Clear completion date if status changes from completed
    }

    project.status = status;
    await project.save();
    return res.json({ id: project._id.toString(), status: project.status, detail: 'Project status updated successfully.' });
  } catch (err) {
    console.error('Failed to update project status:', err);
    return res.status(500).json({ detail: 'Failed to update project status due to an internal server error.' });
  }
});

// Claim project (student)
app.post('/projects/:id/claim', authMiddleware, roleMiddleware(ROLES.STUDENT), async (req, res) => {
  try {
    const projectId = new mongoose.Types.ObjectId(req.params.id);
    const studentId = new mongoose.Types.ObjectId(req.user.id);

    const project = await Project.findById(projectId);
    if (!project) return res.status(404).json({ detail: 'Project not found.' });

    if (project.visibility !== PROJECT_VISIBILITY.PUBLIC) {
      return res.status(400).json({ detail: 'This project is not available for claiming.' });
    }
    if (project.student_ids.length >= project.team_size) {
      return res.status(400).json({ detail: 'This project has reached its maximum team size.' });
    }
    if (project.student_ids.some(x => x.equals(studentId))) {
      return res.status(400).json({ detail: 'You have already claimed this project.' });
    }

    project.student_ids.push(studentId);
    // If the project was 'open' and now has students, set to 'ongoing'.
    // If it was 'pending_approval' (e.g., a student proposed it and another student claimed it),
    // it should remain 'pending_approval' until faculty approves.
    if (project.status === PROJECT_STATUS.OPEN) {
      project.status = PROJECT_STATUS.ONGOING;
    }
    await project.save();

    return res.json({ detail: 'Project claimed successfully.', project_id: project._id.toString() });
  } catch (err) {
    console.error('Failed to claim project:', err);
    return res.status(500).json({ detail: 'Failed to claim project due to an internal server error.' });
  }
});

// Submissions (multipart) - expect field names: project_id, note, files
app.post('/submissions', authMiddleware, roleMiddleware(ROLES.STUDENT), upload.array('files'), async (req, res) => {
  try {
    const { project_id, note } = req.body;
    if (!project_id) return res.status(400).json({ detail: 'Project ID is required.' });

    const project = await Project.findById(project_id);
    if (!project) return res.status(404).json({ detail: 'Project not found.' });

    const studentId = new mongoose.Types.ObjectId(req.user.id);
    if (!project.student_ids.some(x => x.equals(studentId))) {
      return res.status(403).json({ detail: 'You are not assigned to this project.' });
    }

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ detail: 'At least one file is required for submission.' });
    }

    const files = (req.files || []).map(f => path.relative(process.cwd(), f.path));
    const submission = await Submission.create({
      project_id: new mongoose.Types.ObjectId(project_id),
      student_id: studentId,
      note: note || '',
      files,
      status: SUBMISSION_STATUS.PENDING_REVIEW
    });

    // Consider if project status should change here.
    // If a project can have multiple submissions (drafts, final),
    // changing to 'submitted' on first submission might be premature.
    // For now, keeping original logic:
    if (project.status === PROJECT_STATUS.ONGOING) {
      project.status = PROJECT_STATUS.SUBMITTED;
      await project.save();
    }

    return res.status(201).json({ id: submission._id.toString(), detail: 'Submission successful.' });
  } catch (err) {
    console.error('Submission failed:', err);
    return res.status(500).json({ detail: 'Submission failed due to an internal server error.' });
  }
});

// List submissions with filters
app.get('/submissions', authMiddleware, async (req, res) => {
  try {
    const query = {};
    const requestingUserId = new mongoose.Types.ObjectId(req.user.id);
    const requestingUserRole = req.user.role;

    if (req.query.project_id) query.project_id = new mongoose.Types.ObjectId(req.query.project_id);
    if (req.query.student_id) query.student_id = new mongoose.Types.ObjectId(req.query.student_id);
    if (req.query.status && req.query.status !== 'all') {
      if (!Object.values(SUBMISSION_STATUS).includes(req.query.status)) {
        return res.status(400).json({ detail: 'Invalid submission status filter.' });
      }
      query.status = req.query.status;
    }

    // Role-based filtering for submissions
    if (requestingUserRole === ROLES.FACULTY) {
      const facultyProjects = await Project.find({ faculty_id: requestingUserId }).select('_id').lean();
      const facultyProjectIds = facultyProjects.map(p => p._id);
      if (query.project_id && !facultyProjectIds.some(id => id.equals(query.project_id))) {
        return res.status(403).json({ detail: 'Access denied: You are not authorized to view submissions for this project.' });
      }
      query.project_id = { $in: facultyProjectIds };
    } else if (requestingUserRole === ROLES.STUDENT) {
      if (query.student_id && query.student_id.toString() !== requestingUserId.toString()) {
        return res.status(403).json({ detail: 'Access denied: Students can only view their own submissions.' });
      }
      query.student_id = requestingUserId;
    }
    // Admin can see all submissions, no specific role-based query filter needed here.

    if (req.query.search) {
      // Search by project title or student name
      const projectSearch = await Project.find({ title: { $regex: req.query.search, $options: 'i' } }).select('_id').lean();
      const studentSearch = await User.find({ name: { $regex: req.query.search, $options: 'i' }, role: ROLES.STUDENT }).select('_id').lean();

      const searchConditions = [];
      if (projectSearch.length > 0) searchConditions.push({ project_id: { $in: projectSearch.map(p => p._id) } });
      if (studentSearch.length > 0) searchConditions.push({ student_id: { $in: studentSearch.map(s => s._id) } });

      if (searchConditions.length > 0) {
        query.$and = query.$and ? [...query.$and, { $or: searchConditions }] : [{ $or: searchConditions }];
      } else {
        // If no search results, return empty
        return res.json([]);
      }
    }

    const submissions = await Submission.find(query)
      .populate({ path: 'project_id', select: 'title' })
      .populate({ path: 'student_id', select: 'name' })
      .sort({ createdAt: -1 })
      .lean();

    return res.json(submissions.map(s => ({
      id: s._id.toString(),
      project_id: s.project_id._id.toString(),
      project_title: s.project_id.title,
      student_id: s.student_id._id.toString(),
      student_name: s.student_id.name,
      note: s.note,
      files: s.files, // raw file paths
      file_paths: s.files.map(filePath => ({ // objects with name and url
        name: path.basename(filePath),
        url: `${process.env.BASE_URL || 'http://localhost:8000'}/${filePath}`
      })),
      grade: s.grade,
      feedback: s.feedback,
      status: s.status,
      submitted_on: s.createdAt
    })));
  } catch (err) {
    console.error('Failed to fetch submissions:', err);
    return res.status(500).json({ detail: 'Failed to fetch submissions due to an internal server error.' });
  }
});

// Faculty provides feedback/grade on a submission
app.put('/submissions/:id/feedback', authMiddleware, roleMiddleware([ROLES.FACULTY, ROLES.ADMIN]), async (req, res) => {
  try {
    const submissionId = new mongoose.Types.ObjectId(req.params.id);
    const { grade, feedback, project_status_update } = req.body; // Renamed 'status' to 'project_status_update' for clarity

    const submission = await Submission.findById(submissionId);
    if (!submission) return res.status(404).json({ detail: 'Submission not found.' });

    const project = await Project.findById(submission.project_id);
    if (!project) return res.status(404).json({ detail: 'Associated project not found.' });

    // Authorization: Faculty can only provide feedback for projects they supervise. Admin can do any.
    if (req.user.role === ROLES.FACULTY && project.faculty_id && project.faculty_id.toString() !== req.user.id) {
      return res.status(403).json({ detail: 'You are not authorized to provide feedback for this submission.' });
    }

    if (grade !== undefined) {
      if (typeof grade !== 'number' || grade < 0 || grade > 100) {
        return res.status(400).json({ detail: 'Grade must be a number between 0 and 100.' });
      }
      submission.grade = grade;
    }
    if (feedback !== undefined) {
      submission.feedback = feedback;
    }
    submission.status = SUBMISSION_STATUS.REVIEWED; // Mark as reviewed after feedback

    await submission.save();

    // Update project status based on feedback status (optional, controlled by faculty)
    if (project_status_update && Object.values(PROJECT_STATUS).includes(project_status_update)) {
      if (project_status_update === PROJECT_STATUS.COMPLETED && project.status !== PROJECT_STATUS.COMPLETED) {
        project.completedAt = new Date();
      } else if (project_status_update !== PROJECT_STATUS.COMPLETED && project.completedAt) {
        project.completedAt = null;
      }
      project.status = project_status_update;
      await project.save();
    }

    return res.json({ id: submission._id.toString(), detail: 'Feedback submitted successfully.' });
  } catch (err) {
    console.error('Failed to submit feedback:', err);
    return res.status(500).json({ detail: 'Failed to submit feedback due to an internal server error.' });
  }
});

// Analytics - student
app.get('/analytics/student', authMiddleware, roleMiddleware(ROLES.STUDENT), async (req, res) => {
try {
  const studentId = new mongoose.Types.ObjectId(req.user.id);

  const projects = await Project.find({ student_ids: studentId }).lean();
  const submissions = await Submission.find({ student_id: studentId }).lean();

  const total_projects = projects.length;
  const ongoing_projects = projects.filter(p => p.status === PROJECT_STATUS.ONGOING).length;
  const submitted_projects = projects.filter(p => p.status === PROJECT_STATUS.SUBMITTED).length;
  const completed_projects = projects.filter(p => p.status === PROJECT_STATUS.COMPLETED).length;
  const pending_approval_projects = projects.filter(p => p.status === PROJECT_STATUS.PENDING_APPROVAL).length;

  const upcoming_deadlines = projects
    .filter(p => p.deadline && p.status !== PROJECT_STATUS.COMPLETED && p.deadline > new Date())
    .sort((a, b) => a.deadline.getTime() - b.deadline.getTime())
    .slice(0, 5);

  const recent_activity = [];
  submissions.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()).slice(0, 5).forEach(s => {
    const projectTitle = projects.find(p => p._id.equals(s.project_id))?.title || 'Unknown Project';
    recent_activity.push({
      icon: 'fa-file-upload',
      text: `Submitted work for project "${projectTitle}"`,
      date: s.createdAt
      });
    });
    projects.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()).slice(0, 5).forEach(p => {
      if (p.status === PROJECT_STATUS.COMPLETED) {
        recent_activity.push({
          icon: 'fa-check-circle',
          text: `Project "${p.title}" marked as completed`,
          date: p.completedAt || p.createdAt // Use completedAt if available
        });
      } else if (p.status === PROJECT_STATUS.ONGOING && p.student_ids.some(id => id.equals(studentId))) {
        recent_activity.push({
          icon: 'fa-spinner',
          text: `Started working on project "${p.title}"`,
          date: p.createdAt
        });
      }
    });
    recent_activity.sort((a, b) => b.date.getTime() - a.date.getTime());

    const submissionHistoryMap = {};
    submissions.forEach(s => {
      const monthYear = new Date(s.createdAt).toLocaleString('default', { month: 'short', year: 'numeric' });
      submissionHistoryMap[monthYear] = (submissionHistoryMap[monthYear] || 0) + 1;
    });
    const submission_history = Object.keys(submissionHistoryMap).map(key => ({ date: key, count: submissionHistoryMap[key] }));
    submission_history.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

    const gradeDistribution = { '90-100': 0, '80-89': 0, '70-79': 0, '60-69': 0, '0-59': 0 };
    submissions.filter(s => typeof s.grade === 'number').forEach(s => {
      if (s.grade >= 90) gradeDistribution['90-100']++;
      else if (s.grade >= 80) gradeDistribution['80-89']++;
      else if (s.grade >= 70) gradeDistribution['70-79']++;
      else if (s.grade >= 60) gradeDistribution['60-69']++;
      else gradeDistribution['0-59']++;
    });

    return res.json({
      total_projects,
      ongoing_projects,
      submitted_projects,
      completed_projects,
      pending_approval_projects,
      upcoming_deadlines: await Promise.all(upcoming_deadlines.map(populateProjectDetails)),
      recent_activity,
      submission_history,
      grade_distribution: gradeDistribution
    });
  } catch (err) {
    console.error('Failed to compute student analytics:', err);
    return res.status(500).json({ detail: 'Failed to compute student analytics due to an internal server error.' });
  }
});

// Analytics - faculty
app.get('/analytics/faculty', authMiddleware, roleMiddleware([ROLES.FACULTY, ROLES.ADMIN]), async (req, res) => {
  try {
    const facultyId = new mongoose.Types.ObjectId(req.user.id);

    const projects = await Project.find({ faculty_id: facultyId }).lean();
    const projectIds = projects.map(p => p._id);
    const submissions = await Submission.find({ project_id: { $in: projectIds } }).lean();

    const total_projects = projects.length;
    const ongoing_projects = projects.filter(p => p.status === PROJECT_STATUS.ONGOING).length;
    const pending_review_submissions = submissions.filter(s => s.status === SUBMISSION_STATUS.PENDING_REVIEW).length;
    const completed_projects = projects.filter(p => p.status === PROJECT_STATUS.COMPLETED).length;
    const pending_approval_projects = projects.filter(p => p.status === PROJECT_STATUS.PENDING_APPROVAL).length;

    const status_counts = {
      [PROJECT_STATUS.ONGOING]: ongoing_projects,
      [PROJECT_STATUS.SUBMITTED]: projects.filter(p => p.status === PROJECT_STATUS.SUBMITTED).length,
      [PROJECT_STATUS.COMPLETED]: completed_projects,
      [PROJECT_STATUS.PENDING_APPROVAL]: pending_approval_projects,
      [PROJECT_STATUS.REJECTED]: projects.filter(p => p.status === PROJECT_STATUS.REJECTED).length,
      [PROJECT_STATUS.OPEN]: projects.filter(p => p.status === PROJECT_STATUS.OPEN).length,
    };

    const recent_submissions = submissions
      .filter(s => s.status === SUBMISSION_STATUS.PENDING_REVIEW)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, 5);

    const urgent_deadlines = projects
      .filter(p => p.deadline && p.status !== PROJECT_STATUS.COMPLETED && p.deadline > new Date() && (p.deadline.getTime() - new Date().getTime()) / (1000 * 60 * 60 * 24) <= 7)
      .sort((a, b) => a.deadline.getTime() - b.deadline.getTime())
      .slice(0, 5);

    const completionHistoryMap = {};
    projects.filter(p => p.status === PROJECT_STATUS.COMPLETED && p.completedAt).forEach(p => {
      const monthYear = new Date(p.completedAt).toLocaleString('default', { month: 'short', year: 'numeric' });
      completionHistoryMap[monthYear] = (completionHistoryMap[monthYear] || 0) + 1;
    });
    const completion_history = Object.keys(completionHistoryMap).map(key => ({ date: key, count: completionHistoryMap[key] }));
    completion_history.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

    const supervisedStudentIds = new Set();
    projects.forEach(p => p.student_ids.forEach(id => supervisedStudentIds.add(id.toString())));
    const studentPerformance = await Promise.all(Array.from(supervisedStudentIds).map(async (sId) => {
      const student = await User.findById(sId).select('name').lean();
      const studentSubmissions = await Submission.find({ student_id: sId, project_id: { $in: projectIds } }).lean();
      const grades = studentSubmissions.filter(s => typeof s.grade === 'number').map(s => s.grade);
      const avg_grade = grades.length ? parseFloat((grades.reduce((a, b) => a + b, 0) / grades.length).toFixed(2)) : 0;
      return { name: student ? student.name : 'Unknown Student', avg_grade };
    }));

    return res.json({
      total_projects,
      ongoing_projects,
      pending_review_submissions,
      completed_projects,
      pending_approval_projects,
      status_counts,
      recent_submissions: await Promise.all(recent_submissions.map(populateSubmissionDetails)),
      urgent_deadlines: await Promise.all(urgent_deadlines.map(populateProjectDetails)),
      completion_history,
      student_performance: studentPerformance
    });
  } catch (err) {
    console.error('Failed to compute faculty analytics:', err);
    return res.status(500).json({ detail: 'Failed to compute faculty analytics due to an internal server error.' });
  }
});

// Messaging Endpoints
app.post('/messages', authMiddleware, async (req, res) => {
  try {
    const { recipient_id, subject, body } = req.body;
    if (!recipient_id || !subject || !body) {
      return res.status(400).json({ detail: 'Recipient, subject, and body are required.' });
    }

    const recipient = await User.findById(recipient_id);
    if (!recipient) return res.status(404).json({ detail: 'Recipient not found.' });

    const message = await Message.create({
      sender_id: new mongoose.Types.ObjectId(req.user.id),
      recipient_id: new mongoose.Types.ObjectId(recipient_id),
      subject,
      body
    });
    return res.status(201).json({ id: message._id.toString(), detail: 'Message sent successfully.' });
  } catch (err) {
    console.error('Failed to send message:', err);
    return res.status(500).json({ detail: 'Failed to send message due to an internal server error.' });
  }
});

app.get('/messages', authMiddleware, async (req, res) => {
  try {
    const userId = mongoose.Types.ObjectId(req.user.id);
    const query = {
      $or: [{ sender_id: userId }, { recipient_id: userId }]
    };

    if (req.query.search) {
      const searchRegex = { $regex: req.query.search, $options: 'i' };
      query.$or = query.$or.map(cond => ({
        ...cond,
        $or: [
          { subject: searchRegex },
          { body: searchRegex }
        ]
      }));
    }

    const messages = await Message.find(query)
      .populate({ path: 'sender_id', select: 'name' })
      .populate({ path: 'recipient_id', select: 'name' })
      .sort({ createdAt: -1 })
      .lean();

    res.json(messages.map(m => ({
      id: m._id.toString(),
      sender_id: m.sender_id._id.toString(),
      sender_name: m.sender_id.name,
      recipient_id: m.recipient_id._id.toString(),
      recipient_name: m.recipient_id.name,
      subject: m.subject,
      body: m.body,
      read: m.read,
      timestamp: m.createdAt
    })));
  } catch (err) {
    console.error('Failed to fetch messages:', err);
    return res.status(500).json({ detail: 'Failed to fetch messages due to an internal server error.' });
  }
});

app.put('/messages/:id/read', authMiddleware, async (req, res) => {
  try {
    const messageId = mongoose.Types.ObjectId(req.params.id);
    const message = await Message.findById(messageId);
    if (!message) return res.status(404).json({ detail: 'Message not found.' });

    if (message.recipient_id.toString() !== req.user.id) {
      return res.status(403).json({ detail: 'Not authorized to mark this message as read.' });
    }
    message.read = true;
    await message.save();
    return res.json({ id: message._id.toString(), read: true, detail: 'Message marked as read.' });
  } catch (err) {
    console.error('Failed to mark message as read:', err);
    return res.status(500).json({ detail: 'Failed to mark message as read due to an internal server error.' });
  }
});

// Comment Endpoints
app.post('/comments', authMiddleware, async (req, res) => {
  try {
    const { project_id, comment_text } = req.body;
    if (!project_id || !comment_text) {
      return res.status(400).json({ detail: 'Project ID and comment text are required.' });
    }

    const project = await Project.findById(project_id);
    if (!project) return res.status(404).json({ detail: 'Project not found.' });

    const userId = mongoose.Types.ObjectId(req.user.id);
    const isFacultySupervisor = project.faculty_id && project.faculty_id.equals(userId);
    const isAssignedStudent = project.student_ids.some(id => id.equals(userId));
    const isAdmin = req.user.role === ROLES.ADMIN;

    if (!isAdmin && !isFacultySupervisor && !isAssignedStudent) {
      return res.status(403).json({ detail: 'You are not authorized to comment on this project.' });
    }

    const comment = await Comment.create({
      project_id: mongoose.Types.ObjectId(project_id),
      user_id: userId,
      comment_text
    });
    return res.status(201).json({ id: comment._id.toString(), detail: 'Comment added successfully.' });
  } catch (err) {
    console.error('Failed to add comment:', err);
    return res.status(500).json({ detail: 'Failed to add comment due to an internal server error.' });
  }
});

app.get('/comments/:project_id', authMiddleware, async (req, res) => {
  try {
    const projectId = new mongoose.Types.ObjectId(req.params.project_id);
    const requestingUserId = new mongoose.Types.ObjectId(req.user.id);
    const requestingUserRole = req.user.role;

    const project = await Project.findById(projectId).lean();
    if (!project) return res.status(404).json({ detail: 'Project not found.' });

    // Authorization: Only users involved in the project or admins can view comments
    const isFacultySupervisor = project.faculty_id && project.faculty_id.equals(requestingUserId);
    const isAssignedStudent = project.student_ids.some(id => id.equals(requestingUserId));
    const isAdmin = requestingUserRole === ROLES.ADMIN;

    if (!isAdmin && !isFacultySupervisor && !isAssignedStudent) {
      return res.status(403).json({ detail: 'You are not authorized to view comments for this project.' });
    }

    const comments = await Comment.find({ project_id: projectId })
      .populate({ path: 'user_id', select: 'name' })
      .sort({ createdAt: 1 })
      .lean();

    res.json(comments.map(c => ({
      id: c._id.toString(),
      project_id: c.project_id.toString(),
      user_id: c.user_id._id.toString(),
      user_name: c.user_id.name,
      comment_text: c.comment_text,
      timestamp: c.createdAt
    })));
  } catch (err) {
    console.error('Failed to fetch comments:', err);
    return res.status(500).json({ detail: 'Failed to fetch comments due to an internal server error.' });
  }
});

// ===================== Admin Endpoints =====================

// Admin analytics endpoint
app.get('/analytics/admin', authMiddleware, roleMiddleware([ROLES.ADMIN]), async (req, res) => {
    try {
        const users = await User.find({});
        const projects = await Project.find({});
        const submissions = await Submission.find({});
        
        const totalUsers = users.length;
        const studentCount = users.filter(u => u.role === 'student').length;
        const facultyCount = users.filter(u => u.role === 'faculty').length;
        const adminCount = users.filter(u => u.role === 'admin').length;
        
        const totalProjects = projects.length;
        const activeProjects = projects.filter(p => p.status === 'ongoing').length;
        const completedProjects = projects.filter(p => p.status === 'completed').length;
        const pendingApprovals = projects.filter(p => p.status === 'pending_approval').length;
        
        const totalSubmissions = submissions.length;
        const gradedSubmissions = submissions.filter(s => s.grade).length;
        
        res.json({
            users: {
                total: totalUsers,
                students: studentCount,
                faculty: facultyCount,
                admins: adminCount
            },
            projects: {
                total: totalProjects,
                active: activeProjects,
                completed: completedProjects,
                pending_approval: pendingApprovals
            },
            submissions: {
                total: totalSubmissions,
                graded: gradedSubmissions,
                pending: totalSubmissions - gradedSubmissions
            }
        });
    } catch (error) {
        console.error('Error fetching admin analytics:', error);
        res.status(500).json({ detail: 'Internal server error' });
    }
});

// Admin user management endpoints
app.delete('/admin/users/:id', authMiddleware, roleMiddleware([ROLES.ADMIN]), async (req, res) => {
    try {
        const userId = req.params.id;
        
        // Prevent admin from deleting themselves
        if (userId === req.user.id) {
            return res.status(400).json({ detail: 'Cannot delete your own account' });
        }
        
        const user = await User.findByIdAndDelete(userId);
        if (!user) {
            return res.status(404).json({ detail: 'User not found' });
        }
        
        // Also remove user from any projects they're assigned to
        await Project.updateMany(
            { assigned_to: new mongoose.Types.ObjectId(userId) },
            { $pull: { assigned_to: new mongoose.Types.ObjectId(userId) } }
        );
        
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ detail: 'Internal server error' });
    }
});

app.delete('/admin/projects/:id', authMiddleware, roleMiddleware([ROLES.ADMIN]), async (req, res) => {
    try {
        const projectId = req.params.id;
        
        const project = await Project.findByIdAndDelete(projectId);
        if (!project) {
            return res.status(404).json({ detail: 'Project not found' });
        }
        
        // Also delete related submissions
        await Submission.deleteMany({ project_id: new mongoose.Types.ObjectId(projectId) });
        
        res.json({ message: 'Project deleted successfully' });
    } catch (error) {
        console.error('Error deleting project:', error);
        res.status(500).json({ detail: 'Internal server error' });
    }
});

app.delete('/admin/submissions/:id', authMiddleware, roleMiddleware([ROLES.ADMIN]), async (req, res) => {
    try {
        const submissionId = req.params.id;
        
        const submission = await Submission.findByIdAndDelete(submissionId);
        if (!submission) {
            return res.status(404).json({ detail: 'Submission not found' });
        }
        
        res.json({ message: 'Submission deleted successfully' });
    } catch (error) {
        console.error('Error deleting submission:', error);
        res.status(500).json({ detail: 'Internal server error' });
    }
});

// Admin delete user endpoint
app.delete('/admin/users/:id', authMiddleware, roleMiddleware([ROLES.ADMIN]), async (req, res) => {
    try {
        const userId = req.params.id;
        
        // Prevent admin from deleting themselves
        if (req.user.id === userId) {
            return res.status(400).json({ detail: 'Cannot delete your own account' });
        }
        
        // Find and delete the user
        const user = await User.findByIdAndDelete(userId);
        if (!user) {
            return res.status(404).json({ detail: 'User not found' });
        }
        
        // Delete user's projects
        await Project.deleteMany({ createdBy: userId });
        
        // Delete user's submissions
        await Submission.deleteMany({ submittedBy: userId });
        
        res.json({ message: 'User and associated data deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ detail: 'Internal server error' });
    }
});

// Admin system settings endpoint
app.get('/admin/settings', authMiddleware, roleMiddleware([ROLES.ADMIN]), async (req, res) => {
    try {
        // Return system configuration (placeholder)
        res.json({
            system_name: 'ProTracker',
            version: '1.0.0',
            max_file_size: '10MB',
            allowed_file_types: '.pdf,.doc,.docx,.txt',
            maintenance_mode: false,
            registration_enabled: true
        });
    } catch (error) {
        console.error('Error fetching admin settings:', error);
        res.status(500).json({ detail: 'Internal server error' });
    }
});

app.put('/admin/settings', authMiddleware, roleMiddleware([ROLES.ADMIN]), async (req, res) => {
    try {
        // Update system settings (placeholder - in real app, store in database)
        const { maintenance_mode, registration_enabled } = req.body;
        
        // In a real application, you would update these settings in a database
        console.log('Settings updated:', { maintenance_mode, registration_enabled });
        
        res.json({ message: 'Settings updated successfully' });
    } catch (error) {
        console.error('Error updating admin settings:', error);
        res.status(500).json({ detail: 'Internal server error' });
    }
});

// ===================== Admin Endpoints =====================
app.get('/admin/test', authMiddleware, roleMiddleware(ROLES.ADMIN), (req, res) => {
  res.json({ 
    message: 'Admin access working', 
    user: req.user,
    timestamp: new Date().toISOString()
  });
});

// Admin Dashboard Stats
app.get('/admin/stats', authMiddleware, roleMiddleware(ROLES.ADMIN), async (req, res) => {
  try {
    const users = await User.find({}).lean();
    const projects = await Project.find({}).lean();
    const submissions = await Submission.find({}).lean();

    const stats = {
      total_users: users.length,
      active_projects: projects.filter(p => p.status === PROJECT_STATUS.ONGOING).length,
      pending_approvals: projects.filter(p => p.status === PROJECT_STATUS.PENDING_APPROVAL).length,
      total_submissions: submissions.length,
      completed_projects: projects.filter(p => p.status === PROJECT_STATUS.COMPLETED).length,
      user_breakdown: {
        students: users.filter(u => u.role === ROLES.STUDENT).length,
        faculty: users.filter(u => u.role === ROLES.FACULTY).length,
        admins: users.filter(u => u.role === ROLES.ADMIN).length
      },
      project_breakdown: {
        open: projects.filter(p => p.status === PROJECT_STATUS.OPEN).length,
        ongoing: projects.filter(p => p.status === PROJECT_STATUS.ONGOING).length,
        completed: projects.filter(p => p.status === PROJECT_STATUS.COMPLETED).length,
        rejected: projects.filter(p => p.status === PROJECT_STATUS.REJECTED).length
      }
    };

    res.json(stats);
  } catch (error) {
    console.error('Error fetching admin stats:', error);
    res.status(500).json({ detail: 'Failed to fetch admin statistics' });
  }
});

// Admin Analytics Data
app.get('/admin/analytics', authMiddleware, roleMiddleware(ROLES.ADMIN), async (req, res) => {
  try {
    const users = await User.find({}).lean();
    const projects = await Project.find({}).lean();
    const submissions = await Submission.find({}).lean();

    // Recent activity (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const recentUsers = users.filter(u => new Date(u.createdAt) >= thirtyDaysAgo);
    const recentProjects = projects.filter(p => new Date(p.createdAt) >= thirtyDaysAgo);
    const recentSubmissions = submissions.filter(s => new Date(s.createdAt) >= thirtyDaysAgo);

    // Activity timeline (last 7 days)
    const activityTimeline = [];
    for (let i = 6; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      
      const dayUsers = users.filter(u => u.createdAt && new Date(u.createdAt).toISOString().split('T')[0] === dateStr).length;
      const dayProjects = projects.filter(p => p.createdAt && new Date(p.createdAt).toISOString().split('T')[0] === dateStr).length;
      const daySubmissions = submissions.filter(s => s.createdAt && new Date(s.createdAt).toISOString().split('T')[0] === dateStr).length;
      
      activityTimeline.push({
        date: dateStr,
        users: dayUsers,
        projects: dayProjects,
        submissions: daySubmissions
      });
    }

    const analytics = {
      recent_activity: {
        new_users: recentUsers.length,
        new_projects: recentProjects.length,
        new_submissions: recentSubmissions.length
      },
      activity_timeline: activityTimeline,
      user_distribution: users.map(u => ({ role: u.role })),
      project_distribution: projects.map(p => ({ status: p.status })),
      submission_stats: {
        total: submissions.length,
        graded: submissions.filter(s => s.grade !== null).length,
        pending: submissions.filter(s => s.status === SUBMISSION_STATUS.PENDING_REVIEW).length
      }
    };

    res.json(analytics);
  } catch (error) {
    console.error('Error fetching analytics:', error);
    res.status(500).json({ message: 'Error fetching analytics' });
  }
});

// Get admin activity logs
app.get('/admin/logs', authMiddleware, roleMiddleware(ROLES.ADMIN), async (req, res) => {
  try {
    // Mock activity logs - in a real app, you'd have a proper logging system
    const recentUsers = await User.find().sort({ createdAt: -1 }).limit(5);
    const recentProjects = await Project.find().sort({ createdAt: -1 }).limit(5);
    const recentSubmissions = await Submission.find().sort({ createdAt: -1 }).limit(5);
    
    const logs = [
        ...recentUsers.map(user => ({
            id: user._id,
            type: 'user',
            action: 'User registered',
            details: `${user.name} (${user.role}) joined the platform`,
            timestamp: user.createdAt
        })),
        ...recentProjects.map(project => ({
            id: project._id,
            type: 'project',
            action: 'Project created',
            details: `Project "${project.title}" was created`,
            timestamp: project.createdAt
        })),
        ...recentSubmissions.map(submission => ({
            id: submission._id,
            type: 'submission',
            action: 'Submission uploaded',
            details: `New submission for project`,
            timestamp: submission.createdAt
        }))
    ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    res.json(logs);
  } catch (error) {
    console.error('Error fetching admin logs:', error);
    res.status(500).json({ message: 'Error fetching logs' });
  }
});

// Get single submission
app.get('/submissions/:id', authMiddleware, async (req, res) => {
  try {
    const submission = await Submission.findById(req.params.id)
        .populate('project', 'title')
        .populate('student', 'name email');
    
    if (!submission) {
        return res.status(404).json({ message: 'Submission not found' });
    }

    // Check if user has permission to view this submission
    if (req.user.role !== ROLES.ADMIN && 
        req.user.role !== ROLES.FACULTY && 
        submission.student._id.toString() !== req.user.id) {
        return res.status(403).json({ message: 'Access denied' });
    }

    res.json(submission);
  } catch (error) {
    console.error('Error fetching submission:', error);
    res.status(500).json({ message: 'Error fetching submission' });
  }
});

// Update submission (grade/feedback)
app.put('/submissions/:id', authMiddleware, async (req, res) => {
  try {
    const { grade, status, feedback } = req.body;
    
    // Only admin and faculty can update submissions
    if (req.user.role !== ROLES.ADMIN && req.user.role !== ROLES.FACULTY) {
        return res.status(403).json({ message: 'Access denied' });
    }

    const submission = await Submission.findById(req.params.id);
    if (!submission) {
        return res.status(404).json({ message: 'Submission not found' });
    }

    // Update fields if provided
    if (grade !== undefined) submission.grade = grade;
    if (status !== undefined) submission.status = status;
    if (feedback !== undefined) submission.feedback = feedback;
    
    submission.gradedAt = new Date();
    submission.gradedBy = req.user.id;

    await submission.save();

    const updatedSubmission = await Submission.findById(req.params.id)
        .populate('project', 'title')
        .populate('student', 'name email');

    res.json(updatedSubmission);
  } catch (error) {
    console.error('Error updating submission:', error);
    res.status(500).json({ message: 'Error updating submission' });
  }
});

// Delete submission
app.delete('/submissions/:id', authMiddleware, roleMiddleware(ROLES.ADMIN), async (req, res) => {
  try {
    const submission = await Submission.findById(req.params.id);
    if (!submission) {
        return res.status(404).json({ message: 'Submission not found' });
    }

    await Submission.findByIdAndDelete(req.params.id);
    res.json({ message: 'Submission deleted successfully' });
  } catch (error) {
    console.error('Error deleting submission:', error);
    res.status(500).json({ message: 'Error deleting submission' });
  }
});

// ===================== Database Reset Endpoint =====================

// Reset entire database (Admin only - use with extreme caution!)
app.post('/admin/reset-database', authMiddleware, roleMiddleware([ROLES.ADMIN]), async (req, res) => {
    try {
        // Double check admin status for this critical operation
        if (req.user.role !== ROLES.ADMIN) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized: Admin access required'
            });
        }

        // Get counts before deletion
        const userCount = await User.countDocuments();
        const projectCount = await Project.countDocuments();
        const taskCount = await Task.countDocuments();
        const activityCount = await Activity.countDocuments();
        
        // Delete all data from all collections
        await Promise.all([
            User.deleteMany({ _id: { $ne: req.user._id } }), // Keep current admin
            Project.deleteMany({}),
            Task.deleteMany({}),
            Activity.deleteMany({}),
            // Add other collections as needed
        ]);

        res.json({
            success: true,
            message: 'Database reset successful',
            stats: {
                usersDeleted: userCount - 1, // -1 because we keep the current admin
                projectsDeleted: projectCount,
                tasksDeleted: taskCount,
                activitiesDeleted: activityCount
            }
        });
    } catch (error) {
        console.error('Error resetting database:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset database',
            error: error.message
        });
    }
});

// ===================== Serve index.html =====================
app.get('/', (req, res) => {
res.sendFile(path.join(__dirname, 'index.html'));
});

// ===================== User Management Endpoints =====================

// Delete all users (Admin only)
app.delete('/admin/users', authMiddleware, roleMiddleware([ROLES.ADMIN]), async (req, res) => {
    try {
        // Double check admin status for this critical operation
        if (req.user.role !== ROLES.ADMIN) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized: Admin access required'
            });
        }

        // Get count before deletion for the response
        const userCount = await User.countDocuments();
        
        // Delete all users except the current admin
        const result = await User.deleteMany({ 
            _id: { $ne: req.user._id } // Don't delete the current admin
        });

        res.json({
            success: true,
            message: `Successfully deleted ${result.deletedCount} users`,
            deletedCount: result.deletedCount,
            totalUsersBefore: userCount
        });
    } catch (error) {
        console.error('Error deleting users:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete users',
            error: error.message
        });
    }
});

// Get single user by ID
app.get('/users/:id', authMiddleware, roleMiddleware(ROLES.ADMIN), async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-passwordHash');
        if (!user) {
            return res.status(404).json({ detail: 'User not found' });
        }
        
        // Add project count
        const projectCount = await Project.countDocuments({ 
            $or: [
                { student: user._id },
                { faculty: user._id }
            ]
        });
        
        res.json({
            ...user.toObject(),
            project_count: projectCount
        });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ detail: 'Internal server error' });
    }
});

// Update user
app.put('/users/:id', authMiddleware, roleMiddleware(ROLES.ADMIN), async (req, res) => {
    try {
        const { name, email, role } = req.body;
        
        // Validate role
        if (!Object.values(ROLES).includes(role)) {
            return res.status(400).json({ detail: 'Invalid role' });
        }
        
        // Check if email already exists for another user
        const existingUser = await User.findOne({ 
            email: email.toLowerCase(), 
            _id: { $ne: req.params.id } 
        });
        
        if (existingUser) {
            return res.status(400).json({ detail: 'Email already exists' });
        }
        
        const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            { 
                name, 
                email: email.toLowerCase(), 
                role 
            },
            { new: true }
        ).select('-passwordHash');
        
        if (!updatedUser) {
            return res.status(404).json({ detail: 'User not found' });
        }
        
        res.json(updatedUser);
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ detail: 'Internal server error' });
    }
});

// Delete user
app.delete('/users/:id', authMiddleware, roleMiddleware(ROLES.ADMIN), async (req, res) => {
    try {
        const userId = req.params.id;
        
        // Prevent admin from deleting themselves
        if (userId === req.user.id || userId === req.user._id?.toString()) {
            return res.status(400).json({ detail: 'Cannot delete your own account' });
        }
        
        // Handle project reassignment when deleting faculty
        if (req.body.reassignProjects !== false) {
            const userProjects = await Project.find({ faculty: userId });
            
            if (userProjects.length > 0) {
                // Make projects available for claiming by setting faculty to null
                await Project.updateMany(
                    { faculty: userId },
                    { 
                        $unset: { faculty: "" },
                        status: 'available',
                        updatedAt: new Date()
                    }
                );
                
                console.log(`Reassigned ${userProjects.length} projects to be available for claiming`);
            }
        }
        
        const deletedUser = await User.findByIdAndDelete(userId);
        
        if (!deletedUser) {
            return res.status(404).json({ detail: 'User not found' });
        }
        
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ detail: 'Internal server error' });
    }
});

// ===================== Start Server =====================
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`🚀 Backend running on http://localhost:${PORT}`));
