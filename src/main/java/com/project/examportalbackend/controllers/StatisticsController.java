package com.project.examportalbackend.controllers;

import com.project.examportalbackend.services.StatisticsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/statistics")
public class StatisticsController {

    @Autowired
    private StatisticsService statisticsService;

    @GetMapping("/total")
    public StatisticsResponse getStatistics() {
        return new StatisticsResponse(
            statisticsService.getTotalUsers(),
            statisticsService.getTotalQuizzes(),
            statisticsService.getTotalQuestions(),
            statisticsService.getTotalCategories()
        );
    }

    public static class StatisticsResponse {
        private long users;
        private long quizzes;
        private long questions;
        private long categories;

        public StatisticsResponse(long users, long quizzes, long questions, long categories) {
            this.users = users;
            this.quizzes = quizzes;
            this.questions = questions;
            this.categories = categories;
        }

        public long getUsers() {
            return users;
        }

        public long getQuizzes() {
            return quizzes;
        }

        public long getQuestions() {
            return questions;
        }

        public long getCategories() {
            return categories;
        }
    }
}
