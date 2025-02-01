using MediatR;
using Microsoft.Extensions.Logging;
using MySql.Data.MySqlClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Typer.Application.Services;
using Typer.Application.Services.JwtGenerator;
using Typer.Application.Services.PasswordHasher;
using Typer.Domain.Exceptions;
using Typer.Domain.Interfaces.Repositories;

namespace Typer.Application.Commands.Users.CreateUser
{
    public class CreateUserCommandHandler : IRequestHandler<CreateUserCommand, UserDto>
    {
        private readonly IUserRepository _userRepository;
        private readonly IPasswordHasher _passwordHasher;
        private readonly IJwtGenerator _jwtGenerator;
        readonly ILogger<CreateUserCommandHandler> _log;

        public CreateUserCommandHandler(IUserRepository userRepository, IPasswordHasher passwordHasher, IJwtGenerator jwtGenerator, ILogger<CreateUserCommandHandler> log)
        {
            _userRepository = userRepository;
            _passwordHasher = passwordHasher;
            _jwtGenerator = jwtGenerator;
            _log = log;
        }

        public async Task<UserDto> Handle(CreateUserCommand request, CancellationToken cancellationToken)
        {
            try
            {
                _log.LogDebug($"Getting seasons!");
                var salt = _passwordHasher.GenerateSalt();
                _log.LogDebug($"Hashing password!");
                var hashedPassword = _passwordHasher.GenerateHash(request.Password, salt);
                var user = await _userRepository.GetUserByUsername(request.Username);
                if (user != null)
                {
                    _log.LogWarning($"User has omitted UI validation !");
                    throw new TyperBadRequestException("Login jest zajęty");
                };
                user = await _userRepository.GetUserByEmail(request.Email);
                if (user != null) throw new TyperBadRequestException("Email jest zajęty");
                var newUser = Domain.Models.User.Create(request.Username, request.Email, Domain.Enums.Roles.User, hashedPassword, salt);
                await _userRepository.CreateAsync(newUser);
                var token = _jwtGenerator.Generate(newUser.UserId, newUser.Role);
                _log.LogInformation($"user {request.Username} has been created");
                return new UserDto(token, newUser.UserId);
            }
            catch (MySqlException e) when (request.Username.Contains("' OR 1=1; --"))
            {
                _log.LogCritical($"SQL Injection detected!");
                throw;
            }
            catch (Exception e)
            {
                _log.LogError(e, $"Failed to create user {request.Username}");
                throw;
            }
        }
    }
}
