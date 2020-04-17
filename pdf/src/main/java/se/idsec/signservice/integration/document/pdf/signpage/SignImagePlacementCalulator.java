package se.idsec.signservice.integration.document.pdf.signpage;

public interface SignImagePlacementCalulator {
  SignImagePlacement getPlacement(int sigCount, SignImagePlacement basePlacement);
}
