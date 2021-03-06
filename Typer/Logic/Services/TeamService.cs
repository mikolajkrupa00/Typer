﻿using System.Threading.Tasks;
using Typer.Database;
using Typer.Database.Entities;

namespace Typer.Logic.Services
{
    public interface ITeamService
    {
        Task CreateMatch(string teamName); // todo
    }

    public class TeamService : ITeamService
    {
        private readonly TyperContext _context;

        public TeamService(TyperContext context)
        {
            _context = context;
        }

        public async Task CreateMatch(string teamName)
        {
            await _context.AddAsync(new Team
            {
                TeamName = teamName
            });
            await _context.SaveChangesAsync();
        }
    }
}
