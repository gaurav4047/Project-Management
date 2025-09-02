#!/usr/bin/env node

require('dotenv').config();
const mongoose = require('mongoose');

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/protrack';

// Models
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  passwordHash: String,
  role: String,
  createdAt: Date
});

const projectSchema = new mongoose.Schema({
  title: String,
  description: String,
  faculty_id: mongoose.Schema.Types.ObjectId,
  student_ids: [mongoose.Schema.Types.ObjectId],
  status: String,
  deadline: Date,
  visibility: String,
  created_by: mongoose.Schema.Types.ObjectId,
  creator_role: String,
  createdAt: Date
});

const submissionSchema = new mongoose.Schema({
  project_id: mongoose.Schema.Types.ObjectId,
  student_id: mongoose.Schema.Types.ObjectId,
  note: String,
  files: [String],
  grade: Number,
  feedback: String,
  status: String,
  createdAt: Date
});

const messageSchema = new mongoose.Schema({
  sender_id: mongoose.Schema.Types.ObjectId,
  recipient_id: mongoose.Schema.Types.ObjectId,
  subject: String,
  body: String,
  read: Boolean,
  createdAt: Date
});

const commentSchema = new mongoose.Schema({
  project_id: mongoose.Schema.Types.ObjectId,
  user_id: mongoose.Schema.Types.ObjectId,
  comment_text: String,
  createdAt: Date
});

const User = mongoose.model('User', userSchema);
const Project = mongoose.model('Project', projectSchema);
const Submission = mongoose.model('Submission', submissionSchema);
const Message = mongoose.model('Message', messageSchema);
const Comment = mongoose.model('Comment', commentSchema);

async function connectDB() {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('✅ Connected to MongoDB');
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error.message);
    process.exit(1);
  }
}

// Command functions
async function listUsers() {
  const users = await User.find({}).select('-passwordHash').lean();
  console.log('\n📋 All Users:');
  console.log('ID'.padEnd(25) + 'Name'.padEnd(20) + 'Email'.padEnd(30) + 'Role');
  console.log('-'.repeat(80));
  users.forEach(user => {
    console.log(
      user._id.toString().padEnd(25) + 
      (user.name || 'N/A').padEnd(20) + 
      (user.email || 'N/A').padEnd(30) + 
      (user.role || 'N/A')
    );
  });
  console.log(`\nTotal: ${users.length} users\n`);
}

async function listProjects() {
  const projects = await Project.find({}).lean();
  console.log('\n📋 All Projects:');
  console.log('ID'.padEnd(25) + 'Title'.padEnd(30) + 'Status'.padEnd(15) + 'Students');
  console.log('-'.repeat(80));
  projects.forEach(project => {
    console.log(
      project._id.toString().padEnd(25) + 
      (project.title || 'N/A').substring(0, 28).padEnd(30) + 
      (project.status || 'N/A').padEnd(15) + 
      (project.student_ids ? project.student_ids.length : 0)
    );
  });
  console.log(`\nTotal: ${projects.length} projects\n`);
}

async function deleteUserById(userId) {
  try {
    const user = await User.findById(userId);
    if (!user) {
      console.log('❌ User not found');
      return;
    }

    console.log(`Deleting user: ${user.name} (${user.email})`);
    
    // Delete user and related data
    await User.findByIdAndDelete(userId);
    await Project.deleteMany({ created_by: userId });
    await Project.updateMany({}, { $pull: { student_ids: userId } });
    await Project.updateMany({ faculty_id: userId }, { $unset: { faculty_id: 1 } });
    await Submission.deleteMany({ student_id: userId });
    await Message.deleteMany({ $or: [{ sender_id: userId }, { recipient_id: userId }] });
    await Comment.deleteMany({ user_id: userId });

    console.log('✅ User and all related data deleted successfully');
  } catch (error) {
    console.error('❌ Error deleting user:', error.message);
  }
}

async function deleteProjectById(projectId) {
  try {
    const project = await Project.findById(projectId);
    if (!project) {
      console.log('❌ Project not found');
      return;
    }

    console.log(`Deleting project: ${project.title}`);
    
    // Delete project and related data
    await Project.findByIdAndDelete(projectId);
    await Submission.deleteMany({ project_id: projectId });
    await Comment.deleteMany({ project_id: projectId });

    console.log('✅ Project and all related data deleted successfully');
  } catch (error) {
    console.error('❌ Error deleting project:', error.message);
  }
}

async function clearAllData() {
  try {
    await User.deleteMany({});
    await Project.deleteMany({});
    await Submission.deleteMany({});
    await Message.deleteMany({});
    await Comment.deleteMany({});

    console.log('✅ All data cleared from database');
  } catch (error) {
    console.error('❌ Error clearing data:', error.message);
  }
}

async function showStats() {
  try {
    const userCount = await User.countDocuments();
    const projectCount = await Project.countDocuments();
    const submissionCount = await Submission.countDocuments();
    const messageCount = await Message.countDocuments();
    const commentCount = await Comment.countDocuments();

    console.log('\n📊 Database Statistics:');
    console.log(`Users: ${userCount}`);
    console.log(`Projects: ${projectCount}`);
    console.log(`Submissions: ${submissionCount}`);
    console.log(`Messages: ${messageCount}`);
    console.log(`Comments: ${commentCount}`);
    console.log('');
  } catch (error) {
    console.error('❌ Error getting stats:', error.message);
  }
}

// Main execution
async function main() {
  await connectDB();
  
  const command = process.argv[2];
  const param = process.argv[3];

  switch (command) {
    case 'stats':
      await showStats();
      break;
    case 'users':
      await listUsers();
      break;
    case 'projects':
      await listProjects();
      break;
    case 'delete-user':
      if (!param) {
        console.log('❌ Usage: node db-admin.js delete-user <user-id>');
        break;
      }
      await deleteUserById(param);
      break;
    case 'delete-project':
      if (!param) {
        console.log('❌ Usage: node db-admin.js delete-project <project-id>');
        break;
      }
      await deleteProjectById(param);
      break;
    case 'clear-all':
      console.log('⚠️  This will delete ALL data!');
      await clearAllData();
      break;
    default:
      console.log('\n🗄️  ProTracker Database Admin Tool');
      console.log('===================================');
      console.log('Usage: node db-admin.js <command> [parameter]');
      console.log('');
      console.log('Commands:');
      console.log('  stats                    - Show database statistics');
      console.log('  users                    - List all users');
      console.log('  projects                 - List all projects');
      console.log('  delete-user <id>         - Delete user by ID');
      console.log('  delete-project <id>      - Delete project by ID');
      console.log('  clear-all                - Delete all data (DANGER!)');
      console.log('');
      console.log('Examples:');
      console.log('  node db-admin.js stats');
      console.log('  node db-admin.js users');
      console.log('  node db-admin.js delete-user 507f1f77bcf86cd799439011');
      console.log('');
  }

  mongoose.connection.close();
}

main().catch(error => {
  console.error('❌ Application error:', error);
  mongoose.connection.close();
  process.exit(1);
});
