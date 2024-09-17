package com.project.examportalbackend.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.project.examportalbackend.exceptions.InvalidCodeException;
import com.project.examportalbackend.exceptions.UserNotFoundException;
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
        try {
            User user = userRepository.findByEmail(email);
            if (user == null) {
                throw new UserNotFoundException("User not found for email: " + email);
            }

            // Check if a code already exists for the email
            if (verificationCodeStorage.containsKey(email)) {
                System.out.println("Reset code already sent for email: " + email);
                return false;
            }

            String code = generateVerificationCode();
            verificationCodeStorage.put(email, code);
            sendResetCodeEmail(email, code);
            System.out.println("Password reset code sent to: " + email);
            return true;
        } catch (UserNotFoundException e) {
            System.out.println(e.getMessage());
            return false;
        } catch (Exception e) {
            System.out.println("An error occurred while sending the password reset code: " + e.getMessage());
            return false;
        }
    }

    public boolean resetPassword(String email, String code, String newPassword) {
        try {
            String storedCode = verificationCodeStorage.remove(email);
            if (storedCode == null || !storedCode.equals(code)) {
                throw new InvalidCodeException("Invalid or expired code for email: " + email);
            }

            User user = userRepository.findByEmail(email);
            if (user == null) {
                throw new UserNotFoundException("User not found for email: " + email);
            }

            // Retain the raw password before encoding
            String rawPassword = newPassword;
            user.setPassword(passwordEncoder.encode(rawPassword));
            userRepository.save(user);

            // Send email with the new password
            sendNewPasswordEmail(email, rawPassword);

            System.out.println("Password reset successfully for email: " + email);
            return true;
        } catch (InvalidCodeException | UserNotFoundException e) {
            System.out.println(e.getMessage());
            return false;
        } catch (Exception e) {
            System.out.println("An error occurred during the password reset process: " + e.getMessage());
            return false;
        }
    }

    private String generateVerificationCode() {
        return String.format("%06d", new Random().nextInt(1000000));
    }

    // Sends email with the reset code
    private void sendResetCodeEmail(String email, String code) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Password Reset Code");
            message.setText("Your password reset code is: " + code);
            mailSender.send(message);
            System.out.println("Sent email with reset code to: " + email);
        } catch (Exception e) {
            System.out.println("Failed to send reset code email: " + e.getMessage());
        }
    }

    // Sends email with the new password
    private void sendNewPasswordEmail(String email, String newPassword) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Password Reset Successful");
            message.setText("Your password has been successfully reset. Your new password is: " + newPassword);
            mailSender.send(message);
            System.out.println("Sent email with new password to: " + email);
        } catch (Exception e) {
            System.out.println("Failed to send new password email: " + e.getMessage());
        }
    }
}
