/* Shared rule-transaction editor model. Authorities own persistence; no authorization policy is changed here. */
(function(root,factory){if(typeof module==='object'&&module.exports)module.exports=factory();else root.ArrowheadRuleTransactions=factory();})(typeof globalThis==='object'?globalThis:this,function(){
 'use strict';const copy=v=>JSON.parse(JSON.stringify(v)),id=r=>String(r.id??r.uuid??''),binding=r=>JSON.stringify([r.consumer,r.serviceInstanceId]),value=r=>JSON.stringify([r.consumer,r.serviceInstanceId,Number(r.priority)]),definition=r=>r.serviceDefinition||String(r.serviceInstanceId).split('|')[1];
 async function commit(api,candidate,expected){
  if(!Number.isInteger(candidate.priority)||candidate.priority<1||candidate.priority>2147483647)throw Error('Use a positive integer priority.');
  const before=await api.query(),old=expected&&before.find(r=>id(r)===id(expected));
  if(expected&&(!old||value(old)!==value(expected)))throw Error('The rule changed. Reload before saving.');
  if(old&&value(old)===value(candidate))return old;
  if(old&&binding(old)===binding(candidate)){
   await api.modify(id(old),candidate.priority,old);
   try{const rows=await api.query();const row=rows.find(r=>id(r)===id(old)&&value(r)===value(candidate))||rows.find(r=>!before.some(b=>id(b)===id(r))&&value(r)===value(candidate));if(!row||value(row)!==value(candidate))throw Error('Priority not confirmed by authority');return row;}catch(e){e.committed=true;e.message='Priority update reached the authority. Reload to confirm the current state. '+e.message;throw e;}
  }
  if(before.some(r=>binding(r)===binding(candidate)&&(!old||id(r)!==id(old))))throw Error('This consumer is already bound to that instance. Edit its existing connection.');
  const staged=copy(candidate);
  if(old&&old.consumer===candidate.consumer&&definition(old)===definition(candidate)&&Number(old.priority)===candidate.priority){
   const used=new Set(before.filter(r=>r.consumer===candidate.consumer&&definition(r)===definition(candidate)).map(r=>Number(r.priority)));staged.priority=2147483647;while(used.has(staged.priority)&&staged.priority>0)staged.priority--;if(!staged.priority)throw Error('No free staging priority.');
  }
  let created=null,removalAttempted=false,committed=false;
  try{
   const receipt=await api.create(staged);if(!old)committed=true;
   const reported=Array.isArray(receipt?.entries)?receipt.entries:[receipt];created=reported.find(r=>r&&id(r)&&value(r)===value(staged)&&!before.some(b=>id(b)===id(r)))||null;
   const current=await api.query();created=current.find(r=>!before.some(b=>id(b)===id(r))&&value(r)===value(staged))||created;
   if(!created)throw Error('Authority did not confirm a distinct new rule.');
   if(old){const fresh=current.find(r=>id(r)===id(old));if(!fresh||value(fresh)!==value(old))throw Error('The original rule changed during replacement.');removalAttempted=true;await api.remove(id(old));
    if(staged.priority!==candidate.priority)await api.modify(id(created),candidate.priority,created);committed=true;
   }
   const row=(await api.query()).find(r=>id(r)===id(created));if(!row||value(row)!==value(candidate))throw Error('Saved connection could not be confirmed.');return row;
  }catch(error){
   if(committed){error.committed=true;error.message='Save reached the authority. Reload to confirm the current state. '+error.message;throw error;}
   try{
    const current=await api.query();let originalPresent=!old||current.some(r=>id(r)===id(old)||value(r)===value(old));
    if(old&&removalAttempted&&!originalPresent){await api.create({consumer:old.consumer,serviceInstanceId:old.serviceInstanceId,priority:Number(old.priority)});originalPresent=true;}
    if(created&&originalPresent){const fresh=(await api.query()).find(r=>id(r)===id(created));if(fresh&&value(fresh)===value(staged))await api.remove(id(created));}
   }catch{error.message+=' Recovery could not finish; inspect stored rules before retrying.';}
   throw error;
  }
 }
 return{commit};
});
