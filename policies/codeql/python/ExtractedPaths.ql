/**
 * SPDX-License-Identifier: Apache-2.0
 * @name Extracted source paths
 * @description Enumerates database files, not a filesystem inventory.
 * @kind table
 */
import python

from File file
where exists(file.getRelativePath())
select file.getRelativePath() as path
