package com.project.examportalbackend.controllers;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.project.examportalbackend.services.PasswordResetService;

@RestController
@RequestMapping("/api")
public class ForgotPasswordController {

    @Autowired
    private PasswordResetService passwordResetService;

    @PostMapping("/send-reset-code")
    public ResponseEntity<String> sendResetCode(@RequestBody Map<String, String> request) {
        String email = request.get("email");

        if (email == null || email.isEmpty()) {
            return ResponseEntity.badRequest().body("Email is required");
        }

        boolean codeSent = passwordResetService.sendPasswordResetCode(email);

        return codeSent
                ? ResponseEntity.ok("Password reset code sent successfully")
                : ResponseEntity.status(HttpStatus.NOT_FOUND).body("User with the provided email not found");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String code = request.get("code");
        String newPassword = request.get("newPassword");

        if (isEmpty(email, code, newPassword)) {
            return ResponseEntity.badRequest().body("All fields are required");
        }

        boolean isReset = passwordResetService.resetPassword(email, code, newPassword);

        return isReset
                ? ResponseEntity.ok("Password has been reset successfully.")
                : ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid code or reset failed.");
    }

    // Helper method to check if any of the fields are empty
    private boolean isEmpty(String... values) {
        for (String value : values) {
            if (value == null || value.isEmpty()) {
                return true;
            }
        }
        return false;
    }
}
