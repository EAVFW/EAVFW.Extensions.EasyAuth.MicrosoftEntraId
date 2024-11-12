

using EAVFramework.Shared;
using System;

namespace EAVFW.Extensions.EasyAuth.MicrosoftEntraId
{
    [EntityInterface(EntityKey = "Security Group")]
    public interface IEntraIDSecurityGroup
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public Guid? EntraIdGroupId { get; set; }
    }
}