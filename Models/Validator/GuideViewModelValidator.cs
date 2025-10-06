using aspapp.Models.VM;
using FluentValidation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace aspapp.Data.Models.Validator
{
    public class GuideViewModelValidator : AbstractValidator<GuideViewModel>
    {
        public GuideViewModelValidator() {
            RuleFor(x => x.Firstname)
                .NotEmpty().WithMessage("Please specify Firstname");

            RuleFor(x => x.Lastname)
                .NotEmpty().WithMessage("Please specify Lastname");

            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("Please specify Email");

            RuleFor(x => x.Title)
                .NotEmpty().WithMessage("Please specify Title");
        }
    }
}

