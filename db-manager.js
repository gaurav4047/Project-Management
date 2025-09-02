#!/usr/bin/env node

require('dotenv').config();
const mongoose = require('mongoose');
const readline = require('readline');

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/protrack';

// Models (simplified versions)
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

// CLI Interface
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(prompt) {
  return new Promise((resolve) => {
    rl.question(prompt, resolve);
  });
}

async function connectDB() {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('✅ Connected to MongoDB');
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error.message);
    process.exit(1);
  }
}

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

async function listSubmissions() {
  const submissions = await Submission.find({}).lean();
  console.log('\n📋 All Submissions:');
  console.log('ID'.padEnd(25) + 'Project ID'.padEnd(25) + 'Student ID'.padEnd(25) + 'Grade');
  console.log('-'.repeat(100));
  submissions.forEach(sub => {
    console.log(
      sub._id.toString().padEnd(25) + 
      (sub.project_id || 'N/A').toString().padEnd(25) + 
      (sub.student_id || 'N/A').toString().padEnd(25) + 
      (sub.grade || 'N/A')
    );
  });
  console.log(`\nTotal: ${submissions.length} submissions\n`);
}

async function deleteUser() {
  await listUsers();
  const userId = await question('Enter User ID to delete (or "cancel"): ');
  
  if (userId.toLowerCase() === 'cancel') {
    console.log('❌ Operation cancelled');
    return;
  }

  try {
    // Find user first
    const user = await User.findById(userId);
    if (!user) {
      console.log('❌ User not found');
      return;
    }

    console.log(`\n⚠️  You are about to delete user: ${user.name} (${user.email})`);
    const confirm = await question('Type "DELETE" to confirm: ');
    
    if (confirm !== 'DELETE') {
      console.log('❌ Operation cancelled');
      return;
    }

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

async function deleteProject() {
  await listProjects();
  const projectId = await question('Enter Project ID to delete (or "cancel"): ');
  
  if (projectId.toLowerCase() === 'cancel') {
    console.log('❌ Operation cancelled');
    return;
  }

  try {
    const project = await Project.findById(projectId);
    if (!project) {
      console.log('❌ Project not found');
      return;
    }

    console.log(`\n⚠️  You are about to delete project: ${project.title}`);
    const confirm = await question('Type "DELETE" to confirm: ');
    
    if (confirm !== 'DELETE') {
      console.log('❌ Operation cancelled');
      return;
    }

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
  console.log('\n⚠️  DANGER: This will delete ALL data from the database!');
  const confirm1 = await question('Type "CLEAR ALL DATA" to continue: ');
  
  if (confirm1 !== 'CLEAR ALL DATA') {
    console.log('❌ Operation cancelled');
    return;
  }

  const confirm2 = await question('Are you absolutely sure? Type "YES DELETE EVERYTHING": ');
  
  if (confirm2 !== 'YES DELETE EVERYTHING') {
    console.log('❌ Operation cancelled');
    return;
  }

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

async function mainMenu() {
  console.log('\n🗄️  ProTracker Database Manager');
  console.log('================================');
  console.log('1. Show database statistics');
  console.log('2. List all users');
  console.log('3. List all projects');
  console.log('4. List all submissions');
  console.log('5. Delete user (and related data)');
  console.log('6. Delete project (and related data)');
  console.log('7. Clear all data (DANGER!)');
  console.log('8. Exit');
  console.log('');

  const choice = await question('Select an option (1-8): ');

  switch (choice) {
    case '1':
      await showStats();
      break;
    case '2':
      await listUsers();
      break;
    case '3':
      await listProjects();
      break;
    case '4':
      await listSubmissions();
      break;
    case '5':
      await deleteUser();
      break;
    case '6':
      await deleteProject();
      break;
    case '7':
      await clearAllData();
      break;
    case '8':
      console.log('👋 Goodbye!');
      process.exit(0);
    default:
      console.log('❌ Invalid option');
  }

  // Show menu again
  await mainMenu();
}

async function main() {
  await connectDB();
  await mainMenu();
}

// Handle cleanup
process.on('SIGINT', () => {
  console.log('\n👋 Goodbye!');
  rl.close();
  mongoose.connection.close();
  process.exit(0);
});

// Start the application
main().catch(error => {
  console.error('❌ Application error:', error);
  rl.close();
  mongoose.connection.close();
  process.exit(1);
});
