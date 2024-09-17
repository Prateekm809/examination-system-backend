package com.project.examportalbackend.services.implementation;

import com.project.examportalbackend.configurations.JwtUtil;
import com.project.examportalbackend.exceptions.UserAlreadyExistsException;
import com.project.examportalbackend.models.LoginRequest;
import com.project.examportalbackend.models.LoginResponse;
import com.project.examportalbackend.models.Role;
import com.project.examportalbackend.models.User;
import com.project.examportalbackend.repository.RoleRepository;
import com.project.examportalbackend.repository.UserRepository;
import com.project.examportalbackend.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JavaMailSender mailSender; // Inject JavaMailSender

    @Override
    public User registerUserService(User user) throws UserAlreadyExistsException {
        // Check for existing username
        if (userRepository.findByUsername(user.getUsername()) != null) {
            throw new UserAlreadyExistsException("Username already exists");
        }

        // Check for existing email
        if (userRepository.findByEmail(user.getEmail()) != null) {
            throw new UserAlreadyExistsException("Email already exists");
        }

        // Check for existing phone number
        if (userRepository.findByPhoneNumber(user.getPhoneNumber()) != null) {
            throw new UserAlreadyExistsException("Phone number already exists");
        }

        // Set the role for the user
        Role role = roleRepository.findById("USER").orElseThrow(() -> new RuntimeException("Role not found"));
        Set<Role> userRoles = new HashSet<>();
        userRoles.add(role);
        user.setRoles(userRoles);

        // Encrypt and set the password
        String rawPassword = user.getPassword(); // Keep the raw password for the email
        user.setPassword(passwordEncoder.encode(rawPassword));

        // Save the user in the database
        User savedUser = userRepository.save(user);

        // Send welcome email after successful registration
        sendWelcomeEmail(user.getEmail(), user.getUsername(), rawPassword);

        return savedUser;
    }

    @Override
    public LoginResponse loginUserService(LoginRequest loginRequest) throws Exception {
        // Try to find user by username or email
        User user = userRepository.findByUsername(loginRequest.getUsername());
        if (user == null) {
            user = userRepository.findByEmail(loginRequest.getUsername());
        }

        if (user == null) {
            throw new Exception("User not found");
        }

        authenticate(user.getUsername(), loginRequest.getPassword());
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        String token = jwtUtil.generateToken(userDetails);
        return new LoginResponse(user, token);
    }

    private void authenticate(String username, String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }

    // Method to send the welcome email
    private void sendWelcomeEmail(String toEmail, String username, String rawPassword) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject("Welcome to Exam Portal");
        message.setText("Dear " + username + ",\n\nWelcome to Exam Portal! "
                + "Here are your login details:\n\nUsername: " + username + "\nPassword: " + rawPassword 
                + "\n\nPlease keep your credentials secure.\n\nBest Regards,\nExam Portal Team");
        mailSender.send(message);
        System.out.println("Sent welcome email to: " + toEmail);
    }
}
