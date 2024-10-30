import React, { useState } from 'react';
import axios from 'axios';
import styles from './SignUp.module.css';

const SignUp = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [message, setMessage] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const response = await axios.post('YOUR_API_ENDPOINT', {
                email,

                password,
            });
            setMessage('User Registered Successfully');
        } catch (error) {
            setMessage(error.response?.data?.message || 'Error occurred while registering.');
        }
    };

    return (
        <div className={styles.signupContainer}>
            <div className={styles.formWrapper}>
                <h2>Create Your Account</h2>
                <form onSubmit={handleSubmit}>
                    <input
                        type="email"
                        placeholder="Enter Email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className={styles.inputField}
                        required
                    />
                    <input
                        type="password"
                        placeholder="Enter Password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className={styles.inputField}
                        required
                    />
                    <button type="submit" className={styles.submitButton}>
                        Sign Up
                    </button>
                </form>
                {message && <p className={styles.message}>{message}</p>}
            </div>
        </div>
    );
};

export default SignUp;
