﻿using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Typer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class BaseTyperController : ControllerBase
    {
        protected readonly IMediator _mediator;

        public BaseTyperController(IMediator mediator)
        {
            _mediator = mediator;
        }
    }
}
