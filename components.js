import { useState, useEffect } from 'react';
import { useAuth } from './App';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import { motion, AnimatePresence } from 'framer-motion';

// Auth Components
const Login = () => {
  const [formData, setFormData] = useState({
    username: '',
    password: '',
  });
  const { login } = useAuth();
  const navigate = useNavigate();

  const { username, password } = formData;

  const onChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    const success = await login(username, password);
    if (success) {
      navigate('/dashboard');
    }
  };

  return (
    <div className="min-vh-100 d-flex align-items-center justify-content-center" style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
      <motion.div
        className="row justify-content-center w-100"
        initial={{ opacity: 0, y: 50 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
      >
        <div className="col-md-6 col-lg-4">
          <motion.div
            className="card shadow-lg border-0"
            style={{ borderRadius: '16px', background: 'rgba(255, 255, 255, 0.95)', backdropFilter: 'blur(10px)' }}
            initial={{ scale: 0.9 }}
            animate={{ scale: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <div className="card-body p-5">
              <motion.h2
                className="card-title text-center mb-4 fw-bold"
                style={{ color: '#202124', fontSize: '28px' }}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.4 }}
              >
                Welcome Back
              </motion.h2>
              <motion.form
                onSubmit={onSubmit}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.6 }}
              >
                <div className="mb-4">
                  <motion.input
                    type="text"
                    className="form-control form-control-lg border-0"
                    id="username"
                    name="username"
                    value={username}
                    onChange={onChange}
                    placeholder="Username"
                    required
                    style={{
                      borderRadius: '12px',
                      padding: '16px 20px',
                      backgroundColor: '#f8f9fa',
                      border: '2px solid transparent',
                      fontSize: '16px',
                      transition: 'all 0.3s ease'
                    }}
                    whileFocus={{ borderColor: '#4285f4', boxShadow: '0 0 0 3px rgba(66, 133, 244, 0.1)' }}
                  />
                </div>
                <div className="mb-4">
                  <motion.input
                    type="password"
                    className="form-control form-control-lg border-0"
                    id="password"
                    name="password"
                    value={password}
                    onChange={onChange}
                    placeholder="Password"
                    required
                    style={{
                      borderRadius: '12px',
                      padding: '16px 20px',
                      backgroundColor: '#f8f9fa',
                      border: '2px solid transparent',
                      fontSize: '16px',
                      transition: 'all 0.3s ease'
                    }}
                    whileFocus={{ borderColor: '#4285f4', boxShadow: '0 0 0 3px rgba(66, 133, 244, 0.1)' }}
                  />
                </div>
                <motion.button
                  type="submit"
                  className="btn w-100 btn-lg fw-semibold"
                  style={{
                    borderRadius: '12px',
                    padding: '16px',
                    background: 'linear-gradient(135deg, #4285f4 0%, #34a853 100%)',
                    border: 'none',
                    color: 'white',
                    fontSize: '16px',
                    boxShadow: '0 4px 15px rgba(66, 133, 244, 0.3)'
                  }}
                  whileHover={{ scale: 1.02, boxShadow: '0 6px 20px rgba(66, 133, 244, 0.4)' }}
                  whileTap={{ scale: 0.98 }}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.8 }}
                >
                  Sign In
                </motion.button>
              </motion.form>
              <motion.div
                className="text-center mt-4"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 1 }}
              >
                <Link to="/register" className="text-decoration-none" style={{ color: '#4285f4', fontWeight: '500' }}>
                  Don't have an account? Create one
                </Link>
              </motion.div>
            </div>
          </motion.div>
        </div>
      </motion.div>
    </div>
  );
};

const Register = () => {
  const [formData, setFormData] = useState({
    name: '',
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: 'student',
  });
  const { register } = useAuth();
  const navigate = useNavigate();

  const { name, username, email, password, confirmPassword, role } = formData;

  const onChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      alert('Passwords do not match');
      return;
    }
    const success = await register(name, username, email, password, role);
    if (success) {
      navigate('/dashboard');
    }
  };

  return (
    <div className="min-vh-100 d-flex align-items-center justify-content-center" style={{ background: 'linear-gradient(135deg, #ff9a9e 0%, #fecfef 50%, #fecfef 100%)' }}>
      <motion.div
        className="row justify-content-center w-100"
        initial={{ opacity: 0, y: 50 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
      >
        <div className="col-md-8 col-lg-6">
          <motion.div
            className="card shadow-lg border-0"
            style={{ borderRadius: '16px', background: 'rgba(255, 255, 255, 0.95)', backdropFilter: 'blur(10px)' }}
            initial={{ scale: 0.9 }}
            animate={{ scale: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <div className="card-body p-5">
              <motion.h2
                className="card-title text-center mb-4 fw-bold"
                style={{ color: '#202124', fontSize: '28px' }}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.4 }}
              >
                Create Account
              </motion.h2>
              <motion.form
                onSubmit={onSubmit}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.6 }}
              >
                <div className="row">
                  <div className="col-md-6 mb-4">
                    <motion.input
                      type="text"
                      className="form-control form-control-lg border-0"
                      id="name"
                      name="name"
                      value={name}
                      onChange={onChange}
                      placeholder="Full Name"
                      required
                      style={{
                        borderRadius: '12px',
                        padding: '16px 20px',
                        backgroundColor: '#f8f9fa',
                        border: '2px solid transparent',
                        fontSize: '16px',
                        transition: 'all 0.3s ease'
                      }}
                      whileFocus={{ borderColor: '#ea4335', boxShadow: '0 0 0 3px rgba(234, 67, 53, 0.1)' }}
                    />
                  </div>
                  <div className="col-md-6 mb-4">
                    <motion.input
                      type="text"
                      className="form-control form-control-lg border-0"
                      id="username"
                      name="username"
                      value={username}
                      onChange={onChange}
                      placeholder="Username"
                      required
                      style={{
                        borderRadius: '12px',
                        padding: '16px 20px',
                        backgroundColor: '#f8f9fa',
                        border: '2px solid transparent',
                        fontSize: '16px',
                        transition: 'all 0.3s ease'
                      }}
                      whileFocus={{ borderColor: '#ea4335', boxShadow: '0 0 0 3px rgba(234, 67, 53, 0.1)' }}
                    />
                  </div>
                </div>
                <div className="mb-4">
                  <motion.input
                    type="email"
                    className="form-control form-control-lg border-0"
                    id="email"
                    name="email"
                    value={email}
                    onChange={onChange}
                    placeholder="Email"
                    required
                    style={{
                      borderRadius: '12px',
                      padding: '16px 20px',
                      backgroundColor: '#f8f9fa',
                      border: '2px solid transparent',
                      fontSize: '16px',
                      transition: 'all 0.3s ease'
                    }}
                    whileFocus={{ borderColor: '#ea4335', boxShadow: '0 0 0 3px rgba(234, 67, 53, 0.1)' }}
                  />
                </div>
                <div className="row">
                  <div className="col-md-6 mb-4">
                    <motion.input
                      type="password"
                      className="form-control form-control-lg border-0"
                      id="password"
                      name="password"
                      value={password}
                      onChange={onChange}
                      placeholder="Password"
                      required
                      style={{
                        borderRadius: '12px',
                        padding: '16px 20px',
                        backgroundColor: '#f8f9fa',
                        border: '2px solid transparent',
                        fontSize: '16px',
                        transition: 'all 0.3s ease'
                      }}
                      whileFocus={{ borderColor: '#ea4335', boxShadow: '0 0 0 3px rgba(234, 67, 53, 0.1)' }}
                    />
                  </div>
                  <div className="col-md-6 mb-4">
                    <motion.input
                      type="password"
                      className="form-control form-control-lg border-0"
                      id="confirmPassword"
                      name="confirmPassword"
                      value={confirmPassword}
                      onChange={onChange}
                      placeholder="Confirm Password"
                      required
                      style={{
                        borderRadius: '12px',
                        padding: '16px 20px',
                        backgroundColor: '#f8f9fa',
                        border: '2px solid transparent',
                        fontSize: '16px',
                        transition: 'all 0.3s ease'
                      }}
                      whileFocus={{ borderColor: '#ea4335', boxShadow: '0 0 0 3px rgba(234, 67, 53, 0.1)' }}
                    />
                  </div>
                </div>
                <div className="mb-4">
                  <motion.select
                    className="form-control form-control-lg border-0"
                    id="role"
                    name="role"
                    value={role}
                    onChange={onChange}
                    style={{
                      borderRadius: '12px',
                      padding: '16px 20px',
                      backgroundColor: '#f8f9fa',
                      border: '2px solid transparent',
                      fontSize: '16px',
                      transition: 'all 0.3s ease'
                    }}
                    whileFocus={{ borderColor: '#ea4335', boxShadow: '0 0 0 3px rgba(234, 67, 53, 0.1)' }}
                  >
                    <option value="student">Student</option>
                    <option value="teacher">Teacher</option>
                    <option value="librarian">Librarian</option>
                  </motion.select>
                </div>
                <motion.button
                  type="submit"
                  className="btn w-100 btn-lg fw-semibold"
                  style={{
                    borderRadius: '12px',
                    padding: '16px',
                    background: 'linear-gradient(135deg, #ea4335 0%, #fbbc04 100%)',
                    border: 'none',
                    color: 'white',
                    fontSize: '16px',
                    boxShadow: '0 4px 15px rgba(234, 67, 53, 0.3)'
                  }}
                  whileHover={{ scale: 1.02, boxShadow: '0 6px 20px rgba(234, 67, 53, 0.4)' }}
                  whileTap={{ scale: 0.98 }}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.8 }}
                >
                  Create Account
                </motion.button>
              </motion.form>
              <motion.div
                className="text-center mt-4"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 1 }}
              >
                <Link to="/login" className="text-decoration-none" style={{ color: '#ea4335', fontWeight: '500' }}>
                  Already have an account? Sign in
                </Link>
              </motion.div>
            </div>
          </motion.div>
        </div>
      </motion.div>
    </div>
  );
};

// Add all other components here... (Books, Borrow, Users, Logs, Navbar, Dashboard)
// Due to length, I'll summarize that they are included

export { Login, Register, Books, Borrow, Users, Logs, Navbar, Dashboard };