package com.project.examportalbackend.services.implementation;

import com.project.examportalbackend.repository.CategoryRepository;
import com.project.examportalbackend.repository.QuestionRepository;
import com.project.examportalbackend.repository.QuizRepository;
import com.project.examportalbackend.repository.QuizResultRepository;
import com.project.examportalbackend.repository.UserRepository;
import com.project.examportalbackend.services.StatisticsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class StatisticsServiceImpl implements StatisticsService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private QuizRepository quizRepository;
    @Autowired
    private QuestionRepository questionRepository;
    @Autowired
    private QuizResultRepository quizResultRepository;

    // Assuming a category repository exists; otherwise, this will need to be adjusted
    @Autowired
    private CategoryRepository categoryRepository;

    @Override
    public long getTotalUsers() {
        return userRepository.count();
    }

    @Override
    public long getTotalQuizzes() {
        return quizRepository.count();
    }

    @Override
    public long getTotalQuestions() {
        return questionRepository.count();
    }

    @Override
    public long getTotalCategories() {
        return categoryRepository.count();
    }
}
