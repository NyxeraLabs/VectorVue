/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
*/

import { renderCliFooter, renderCliHeader, renderPanel, renderSectionTitle, renderStatus } from './branding';

export function renderExample(): string {
  return [
    renderCliHeader('Threat Intelligence Command Interface'),
    '',
    renderSectionTitle('Latest Findings'),
    renderPanel(
      [
        renderStatus('success', 'Tenant telemetry synchronized.'),
        renderStatus('warning', '2 assets missing EDR heartbeat.'),
        renderStatus('error', '1 control validation failed.')
      ].join('\n'),
      'Ops Snapshot'
    ),
    renderCliFooter()
  ].join('\n');
}
