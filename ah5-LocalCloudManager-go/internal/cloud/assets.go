// SPDX-License-Identifier: EPL-2.0
package cloud

import "embed"

// Relocation must not leave the executable dependent on its build checkout.
//
//go:embed ui/index.html ui/app.js ui/styles.css
var managerAssets embed.FS
