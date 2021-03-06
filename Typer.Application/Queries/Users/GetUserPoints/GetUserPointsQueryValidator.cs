﻿using FluentValidation;
using System;
using System.Collections.Generic;
using System.Text;

namespace Typer.Application.Queries.Users.GetUserPoints
{
    class GetUserPointsQueryValidator : AbstractValidator<GetUserPointsQuery>
    {
        public GetUserPointsQueryValidator()
        {
            RuleFor(x => x.UserId).NotEmpty().WithMessage("brak id użytkownika");
        }
    }
}
