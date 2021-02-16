﻿using System;
using System.Collections.Generic;
using System.Text;

namespace Typer.Application.Queries.MatchPredictions.GetCurrentGameweekPredictions
{
    public class MatchPredictionDto
    {
        public MatchPredictionDto(Guid? matchPredictionId, int? homeTeamGoals, int? awayTeamGoals, string homeTeamName,
            string awayTeamName, int? homeTeamGoalsPrediction, int? awayTeamGoalsPrediction, DateTime matchDate, Guid gameweekId)
        {
            MatchPredictionId = matchPredictionId;
            HomeTeamName = homeTeamName;
            AwayTeamName = awayTeamName;
            HomeTeamGoals = homeTeamGoals;
            AwayTeamGoals = awayTeamGoals;
            HomeTeamGoalsPrediction = homeTeamGoalsPrediction;
            AwayTeamGoalsPrediction = awayTeamGoalsPrediction;
            MatchDate = matchDate;
            GameweekId = gameweekId;
        }

        public Guid? MatchPredictionId { get; set; }
        public string HomeTeamName { get; set; }
        public string AwayTeamName { get; set; }
        public int? HomeTeamGoals { get; set; }
        public int? AwayTeamGoals { get; set; }
        public int? HomeTeamGoalsPrediction { get; set; }
        public int? AwayTeamGoalsPrediction { get; set; }
        public DateTime MatchDate { get; set; }
        public Guid GameweekId { get; set; }
    }
}
