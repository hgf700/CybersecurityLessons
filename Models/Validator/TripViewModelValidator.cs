//using FluentValidation;
//using aspapp.Models.VM;
//using System.Linq;

//namespace aspapp.Models.Validator
//{
//    public class TripViewModelValidator : AbstractValidator<TripViewModel>
//    {
//        public TripViewModelValidator()
//        {
//            RuleFor(x => x.Destination)
//                .NotEmpty().WithMessage("Please specify Destination");

//            RuleFor(x => x.StartDate)
//                .NotEmpty().WithMessage("Please specify StartDate");

//            RuleFor(x => x.EndDate)
//                .NotEmpty().WithMessage("Please specify EndDate");
//                //.GreaterThan(x => x.StartDate).WithMessage("EndDate must be after StartDate");

//            RuleFor(x => x.GuideId)
//                .GreaterThan(0).WithMessage("Please select a Guide");

//            RuleFor(x => x.Guides)
//                .NotNull().WithMessage("Lista przewodników nie może być null.")
//                .WithMessage("Musi być przynajmniej jeden przewodnik dostępny.");

//            RuleFor(x => x.Travelers)
//                .NotNull().WithMessage("Lista podróżników nie może być null.")
//                .WithMessage("Musi być przynajmniej jeden podróżnik dostępny.");
//        }
//    }
//}
