// Shared, explicit role-to-direction policy. Unknown values fail closed.
export const REHAB_ROLES = Object.freeze(['rehab1_physician','psychologist','speech_therapist','exercise_therapist','rehab2_physician']);
export const INVITE_ROLES = Object.freeze(['neurologist','intensivist','cardiologist','bot',...REHAB_ROLES]);
export const ROLES = Object.freeze(['admin',...INVITE_ROLES]);
export const GROUPS = Object.freeze(['cardiology','orit','rehab1','rehab2']);
export const ROLE_LABELS = Object.freeze({admin:'Организатор ПСО',neurologist:'Невролог ПСО',intensivist:'Реаниматолог',cardiologist:'Кардиолог',bot:'Бот поступлений',rehab1_physician:'Реабилитолог · I этап',psychologist:'Медицинский психолог · I этап',speech_therapist:'Логопед · I этап',exercise_therapist:'Методист ЛФК · I этап',rehab2_physician:'Реабилитолог ОМР · II этап'});
export const GROUP_LABELS = Object.freeze({cardiology:'ПСО · Кардиолог',orit:'ПСО · ОРИТ',rehab1:'Реабилитация · I этап',rehab2:'ОМР · II этап'});
const members = Object.freeze({cardiology:Object.freeze(['cardiologist']),orit:Object.freeze(['intensivist']),rehab1:Object.freeze(REHAB_ROLES.slice(0,4)),rehab2:Object.freeze(['rehab2_physician'])});
export const rolesForGroup = group => members[group] || [];
export const roleGroup = role => GROUPS.find(group => rolesForGroup(group).includes(role)) || null;
export const isRehabGroup = group => group === 'rehab1' || group === 'rehab2';
export const isReplyKind = kind => kind === 'reply' || kind === 'group_reply';
export const isGroupConversationKind = kind => kind === 'group_reply' || kind === 'discussion';
// PSO clinicians and the specialists of exactly one direction take part in
// group conversations. A bot never receives or replies to these messages.
export const participatesInGroup = (role,group) => GROUPS.includes(group) &&
  (role === 'admin' || role === 'neurologist' || roleGroup(role) === group);
export function canSendGroup(role,group,kind) {
  if (!GROUPS.includes(group)) return false;
  if (kind === 'group_reply') return participatesInGroup(role,group);
  if (kind === 'discussion') return group === 'rehab1' && participatesInGroup(role,group);
  if (isRehabGroup(group)) return kind === 'review' && ['admin','neurologist'].includes(role);
  if (kind === 'admission') return role === 'bot';
  if (kind === 'review') return ['admin','neurologist'].includes(role);
  return kind === 'reply' && ['admin','neurologist','cardiologist','intensivist'].includes(role);
}
