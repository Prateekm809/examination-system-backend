package com.project.examportalbackend.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.project.examportalbackend.models.User;
import com.project.examportalbackend.repository.UserRepository;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Random;

@Service
public class PasswordResetService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private final ConcurrentHashMap<String, String> verificationCodeStorage = new ConcurrentHashMap<>();

    public boolean sendPasswordResetCode(String email) {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            System.out.println("User not found for email: " + email);
            return false;
        }

        // Check if a code already exists for the email
        if (verificationCodeStorage.containsKey(email)) {
            System.out.println("Reset code already sent for email: " + email);
            return false; // Or you can choose to send another code if desired
        }

        String code = generateVerificationCode();
        verificationCodeStorage.put(email, code);
        sendEmail(email, code);
        System.out.println("Password reset code sent to: " + email);
        return true;
    }

    public boolean resetPassword(String email, String code, String newPassword) {
        String storedCode = verificationCodeStorage.remove(email);
        if (storedCode == null || !storedCode.equals(code)) {
            System.out.println("Invalid or expired code for email: " + email);
            return false;
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            System.out.println("User not found for email: " + email);
            return false;
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        System.out.println("Password reset successfully for email: " + email);
        return true;
    }

    private String generateVerificationCode() {
        return String.format("%06d", new Random().nextInt(1000000));
    }

    private void sendEmail(String email, String code) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Password Reset Code");
        message.setText("Your password reset code is: " + code);
        mailSender.send(message);
        System.out.println("Sent email with reset code to: " + email);
    }
}