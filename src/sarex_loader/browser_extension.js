async (selectedPage, options) => {
  const context = selectedPage.context();
  let state = context.__sarexMetadata;
  const noWorkers = async page => {
    const value = await page.evaluate(async () => ({
      controlled: !!navigator.serviceWorker?.controller,
      registered: navigator.serviceWorker ? (await navigator.serviceWorker.getRegistrations()).length : 0
    })).catch(() => {throw new Error('SAREX_TREE_WORKER_CHECK_FAILED')});
    if (value.controlled || value.registered) throw new Error('SAREX_TREE_SERVICE_WORKER_PRESENT');
  };
  if (!state) {
    if (!/^https:\/\/lk\.sarex\.io\/documentations(?:\/\d+)?\/?$/.test(selectedPage.url()))
      throw new Error('SAREX_TREE_WRONG_TAB');
    await noWorkers(selectedPage);
    state = {ownedPage: await context.newPage(), folder: options.folder, disk: options.disk, blocked: 0};
    context.__sarexMetadata = state;
    await state.ownedPage.addInitScript(() => {
      if (navigator.serviceWorker) Object.defineProperty(navigator.serviceWorker, 'register', {
        configurable: false, value: () => Promise.reject(new Error('Read-only metadata collection'))
      });
    });
    await state.ownedPage.route('**/*', async route => {
      const request = route.request();
      const url = new URL(request.url());
      if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method())) {
        state.blocked++;
        return route.abort();
      }
      if (url.protocol !== 'https:' || url.username || url.password
          || (url.port && url.port !== '443')
          || !['lk.sarex.io', 'api.sarex.io', 'modules.sarex.io'].includes(url.hostname)
          || /\.pdf(?:$|\/)|download|\/workspaces|\/bundles(?:\/|$)|upload|\/files(?:\/|$)|\/preview|\/thumbnail|\/content(?:\/|$)/i.test(url.pathname))
        return route.abort();
      if (url.hostname === 'modules.sarex.io') {
        const query = [...url.searchParams];
        if (url.pathname.split('/').includes('..')
            || !/^\/documentations\/static\/[A-Za-z0-9_./-]+\.(?:js|css|woff2?|svg|png)$/.test(url.pathname)
            || !(query.length === 0 || (query.length === 1 && query[0][0] === 'ts'
                 && /^[0-9]{1,16}$/.test(query[0][1])))) return route.abort();
      }
      if (url.pathname.includes('/gateway/api/') && /\/disks\/[^/]+\/documents\/?$/.test(url.pathname)
          && !matches(request.url(), request.method(), state)) return route.abort();
      if (request.isNavigationRequest() && request.frame() === state.ownedPage.mainFrame()
          && request.url() !== `https://lk.sarex.io/documentations/${state.folder}`)
        return route.abort();
      return route.continue();
    });
    await state.ownedPage.routeWebSocket('**/*', socket => socket.close());
  }
  function matches(address, method, scope) {
    const url = new URL(address);
    const query = [...url.searchParams];
    return method === 'GET' && url.origin === 'https://api.sarex.io'
      && url.pathname === `/gateway/api/v1/disks/${scope.disk}/documents`
      && query.length === 1 && ['child_id', 'parent_id'].includes(query[0][0])
      && query[0][1] === String(scope.folder);
  }
  if (state.disk !== options.disk || !Number.isSafeInteger(options.folder) || options.folder <= 0)
    throw new Error('SAREX_TREE_SCOPE_INVALID');
  const page = state.ownedPage;
  if (page.isClosed()) throw new Error('SAREX_TREE_PAGE_CLOSED');
  if (page.url().startsWith('https://lk.sarex.io/')) await noWorkers(page);
  state.folder = options.folder;
  const pending = page.waitForResponse(r => matches(r.url(), r.request().method(), state), {timeout:45000});
  pending.catch(() => {});
  await page.goto(`https://lk.sarex.io/documentations/${options.folder}`,
                  {waitUntil:'domcontentloaded', timeout:45000})
    .catch(() => {throw new Error('SAREX_TREE_NAVIGATION_FAILED')});
  const response = await pending.catch(() => {throw new Error('SAREX_TREE_GATEWAY_TIMEOUT')});
  if (response.status() !== 200 || response.request().redirectedFrom() || response.fromServiceWorker())
    throw new Error('SAREX_TREE_HTTP_REJECTED');
  const mime = await response.headerValue('content-type') || '';
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(mime))
    throw new Error('SAREX_TREE_CONTENT_TYPE_INVALID');
  const length = await response.headerValue('content-length');
  if (length && (!/^\d+$/.test(length) || Number(length) > options.limit))
    throw new Error('SAREX_TREE_RESPONSE_TOO_LARGE');
  const body = await response.body().catch(() => {throw new Error('SAREX_TREE_BODY_FAILED')});
  if (body.length > options.limit) throw new Error('SAREX_TREE_RESPONSE_TOO_LARGE');
  let data;
  try {data = JSON.parse(body.toString('utf8'))}
  catch {throw new Error('SAREX_TREE_JSON_INVALID')}
  if (!Array.isArray(data.documents)) throw new Error('SAREX_TREE_SCOPE_INVALID');
  const payload = {documents: data.documents.map(d => ({
    id:d.id, name:d.name, path:d.path, is_folder:d.is_folder
  }))};
  for (const key of ['count', 'total', 'next', 'has_more', 'has_next', 'next_page', 'pagination'])
    if (Object.hasOwn(data, key)) payload[key] = data[key];
  return {folder_id:options.folder, received_at:new Date().toISOString(), status:200,
          blocked_mutations:state.blocked, payload};
}
