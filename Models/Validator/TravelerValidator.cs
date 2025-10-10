using FluentValidation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace aspapp.Models.Validator
{
    public class TravelerValidator : AbstractValidator<Traveler>
    {
        public TravelerValidator()
        {

            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("Email or password is incorrect");

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("Email or password is incorrect");

        }
    }
}
