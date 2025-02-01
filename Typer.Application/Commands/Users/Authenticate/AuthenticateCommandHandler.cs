using MediatR;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Typer.Application.Services.JwtGenerator;
using Typer.Application.Services.PasswordHasher;
using Typer.Domain.Exceptions;
using Typer.Domain.Interfaces.Repositories;
using Microsoft.Extensions.Logging;

namespace Typer.Application.Commands.Users.Authenticate
{
    public class AuthenticateCommandHandler : IRequestHandler<AuthenticateCommand, UserDto>
    {
        private readonly IUserRepository _userRepository;
        private readonly IJwtGenerator _jwtGenerator;
        private readonly IPasswordHasher _passwordHasher;
        readonly ILogger<AuthenticateCommandHandler> _log;

        public AuthenticateCommandHandler(IUserRepository userRepository, IJwtGenerator jwtGenerator, IPasswordHasher passwordHasher, ILogger<AuthenticateCommandHandler> log)
        {
            _userRepository = userRepository;
            _jwtGenerator = jwtGenerator;
            _passwordHasher = passwordHasher;
            _log = log;
        }

        public async Task<UserDto> Handle(AuthenticateCommand request, CancellationToken cancellationToken)
        {
            var user = await _userRepository.GetUserByUsername(request.Username);
            if(user==null)
            {
                _log.LogInformation($"user has tried to login using not existing username {request.Username}");
                throw new TyperUnauthorizedException("niepoprawne dane");
            }
            var hashedPassword = _passwordHasher.GenerateHash(request.Password, user.Salt);
            var token = _jwtGenerator.Generate(user.UserId, user.Role);
            if (_passwordHasher.GenerateHash(request.Password, user.Salt) == user.Password)
                return new UserDto(user.Username, user.Role, user.UserId, token);
            _log.LogInformation($"user {request.Username} tried to login using invalid password");
            throw new TyperUnauthorizedException("niepoprawne dane");
        }
    }
}
