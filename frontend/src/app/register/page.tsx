'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import api from '../../utils/api';

export default function RegisterPage() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await api.post('/auth/register', { name, email, password });
      const { token } = response.data;
      
      localStorage.setItem('token', token);
      document.cookie = `token=${token}; path=/; max-age=86400; SameSite=Lax;`;
      router.push('/dashboard');
    } catch (err: any) {
      console.error(err);
      setError(
        err.response?.data?.message || 
        err.response?.data?.errors?.email?.message ||
        'Registration failed. Please check the requirements.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '40px', maxWidth: '400px', margin: 'auto' }}>
      <h1>API Sentinel - Register</h1>
      
      {error && <div style={{ color: 'red', marginBottom: '15px' }}>{error}</div>}

      <form onSubmit={handleRegister}>
        <div style={{ marginBottom: '15px' }}>
          <label htmlFor="name" style={{ display: 'block', marginBottom: '5px' }}>Full Name</label>
          <input
            id="name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            style={{ width: '100%', padding: '8px' }}
          />
        </div>

        <div style={{ marginBottom: '15px' }}>
          <label htmlFor="email" style={{ display: 'block', marginBottom: '5px' }}>Email Address</label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            style={{ width: '100%', padding: '8px' }}
          />
        </div>

        <div style={{ marginBottom: '15px' }}>
          <label htmlFor="password" style={{ display: 'block', marginBottom: '5px' }}>Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{ width: '100%', padding: '8px' }}
          />
        </div>

        <button 
          id="register-btn" 
          type="submit" 
          disabled={loading}
          style={{ width: '100%', padding: '10px', backgroundColor: '#0070f3', color: 'white', border: 'none', cursor: 'pointer' }}
        >
          {loading ? 'Registering...' : 'Register'}
        </button>
      </form>

      <p style={{ marginTop: '20px' }}>
        Already have an account? <a href="/login">Login here</a>
      </p>
    </div>
  );
}
