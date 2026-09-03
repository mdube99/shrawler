(() => {
  'use strict';
  const fragment = new URLSearchParams(location.hash.slice(1));
  const token = fragment.get('token') || '';
  history.replaceState(null, '', location.pathname);
  const $ = id => document.getElementById(id);
  let page = 1, hasNext = false, selected = null, timer = null, controller = null, objectUrl = null;
  const api = async (path, options = {}) => {
    options.headers = Object.assign({}, options.headers, {Authorization: `Bearer ${token}`});
    const response = await fetch(path, options);
    if (!response.ok) { let message = `Request failed (${response.status})`; try { message = (await response.json()).error; } catch (_) {} throw new Error(message); }
    return response;
  };
  const appendOptions = (id, values) => values.forEach(value => { const option = document.createElement('option'); option.value = value; option.textContent = value || '(none)'; $(id).append(option); });
  const text = (parent, label, value) => { const dt = document.createElement('dt'); dt.textContent = label; const dd = document.createElement('dd'); dd.textContent = value || '—'; parent.append(dt, dd); };
  const closeObject = () => { if (objectUrl) URL.revokeObjectURL(objectUrl); objectUrl = null; };
  const openDetails = item => {
    selected = item; $('detail-name').textContent = item.file_name; $('metadata').replaceChildren();
    [['UNC path', item.unc_path], ['Host', item.host], ['Share', item.share], ['Remote path', item.remote_path], ['Size', item.readable_size || String(item.size_bytes)], ['Modified', item.mtime_utc]].forEach(row => text($('metadata'), row[0], row[1]));
    $('details').hidden = false;
  };
  const search = async () => {
    if (controller) controller.abort(); controller = new AbortController();
    const params = new URLSearchParams({q:$('query').value,host:$('host').value,share:$('share').value,extension:$('extension').value,page:String(page)});
    try {
      const data = await (await api(`/api/files?${params}`, {signal:controller.signal})).json();
      const body = $('results'); body.replaceChildren();
      data.items.forEach(item => { const row = document.createElement('tr'); [item.file_name,item.host,item.share,item.readable_size || String(item.size_bytes),item.mtime_utc,item.remote_path].forEach(value => { const cell=document.createElement('td'); cell.textContent=value || '—'; row.append(cell); }); row.addEventListener('click',()=>openDetails(item)); body.append(row); });
      hasNext=data.has_next; $('previous').disabled=page===1; $('next').disabled=!hasNext; $('page').textContent=`Page ${page}`; $('summary').textContent=`${data.total.toLocaleString()} matching files`;
    } catch (error) { if (error.name !== 'AbortError') $('summary').textContent=error.message; }
  };
  const schedule = () => { page=1; clearTimeout(timer); timer=setTimeout(search,250); };
  const preview = async () => {
    closeObject(); $('preview-text').textContent=''; $('preview-image').hidden=true; $('preview-pdf').hidden=true; $('preview-message').textContent='Loading…'; $('preview-dialog').showModal();
    try { const response=await api(`/api/files/${selected.id}/preview`); const type=response.headers.get('content-type') || ''; $('preview-message').textContent='';
      if(type.startsWith('application/json')) { const data=await response.json(); $('preview-text').textContent=data.content; }
      else { objectUrl=URL.createObjectURL(await response.blob()); if(type==='application/pdf'){$('preview-pdf').src=objectUrl;$('preview-pdf').hidden=false;}else{$('preview-image').src=objectUrl;$('preview-image').hidden=false;} }
    } catch(error){ $('preview-message').textContent=error.message; }
  };
  const download = async () => { try { const response=await api(`/api/files/${selected.id}/download`); const url=URL.createObjectURL(await response.blob()); const link=document.createElement('a'); link.href=url; link.download=selected.file_name; link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000); } catch(error){ alert(error.message); } };
  Promise.all([api('/api/status').then(r=>r.json()),api('/api/facets').then(r=>r.json())]).then(([status,facets])=>{ $('status').textContent=`${status.results_name} · ${status.file_count.toLocaleString()} files`; appendOptions('host',facets.hosts);appendOptions('share',facets.shares);appendOptions('extension',facets.extensions);search(); }).catch(error=>$('status').textContent=error.message);
  $('query').addEventListener('input',schedule); ['host','share','extension'].forEach(id=>$(id).addEventListener('change',schedule)); $('clear').addEventListener('click',()=>{$('query').value='';['host','share','extension'].forEach(id=>$(id).value='');schedule();});
  $('previous').addEventListener('click',()=>{if(page>1){page--;search();}}); $('next').addEventListener('click',()=>{if(hasNext){page++;search();}}); $('close-details').addEventListener('click',()=>$('details').hidden=true); $('preview').addEventListener('click',preview); $('download').addEventListener('click',download);
  $('close-preview').addEventListener('click',()=>{$('preview-dialog').close();closeObject();}); $('stop').addEventListener('click',async()=>{if(confirm('Stop the local Shrawler server?')) await api('/api/shutdown',{method:'POST',headers:{Origin:location.origin}});});
  document.addEventListener('keydown',event=>{if(event.key==='/'&&document.activeElement!==$('query')){event.preventDefault();$('query').focus();}if(event.key==='Escape')$('details').hidden=true;});
})();
