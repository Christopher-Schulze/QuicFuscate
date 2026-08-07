<script lang="ts">
  import { AboutContent } from "@quicfuscate/ui";
  import appLogo from "../../../../../../assets/logo/QuicFuscate_clean.png";

  // Injected from the single release-version owner; never a literal.
  const version = `v${__RELEASE_VERSION__}`;
</script>

<div class="flex-1 h-full min-h-0 overflow-hidden">
  <div class="flex h-[640px] w-[748px]">
    <AboutContent {version} logoSrc={appLogo} />
  </div>
</div>
