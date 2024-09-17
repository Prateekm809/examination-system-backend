package com.project.examportalbackend.repository;

import com.project.examportalbackend.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
    User findByEmail(String email); // Add this method
    User findByPhoneNumber(String phoneNumber); // Add this method
}
