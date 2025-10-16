<?php
// classes/GError.php

/**
 * GError - Sistema robusto de validación y filtrado con manejo de errores
 * 
 * @author Sistema de Autenticación
 * @version 2.0
 */
class GError {
    // Constantes HTTP
    public const notFound = 404;
    public const forbidden = 403;
    public const badRequest = 400;
    public const unauthorized = 401;
    public const conflict = 409;
    public const unprocessable = 422;
    
    // Tipos de filtro
    public const inclusive = "i";        // Lista blanca
    public const exclusive = "e";        // Lista negra
    public const all_match = "a";        // Todas las condiciones
    public const strict_exclude = "s";   // Excluir si todas son true
    
    // Propiedades privadas
    private string $name;
    private int $errorType;
    private string $filterType;
    private array $samples;
    private string $origin;
    private bool $autoThrow;
    private string $errMessage;
    private array $residue = [];
    private array $errDetails = [];
    
    /**
     * Constructor
     */
    public function __construct(
        string $name,
        int $errorType,
        string $filterType,
        array $samples,
        ?string $origin = "origen desconocido",
        ?bool $autoThrow = false,
        ?string $errMessage = "Error encontrado"
    ) {
        $this->name = $name;
        $this->errorType = $errorType;
        $this->filterType = $filterType;
        $this->samples = $samples;
        $this->origin = $origin ?? "origen desconocido";
        $this->autoThrow = $autoThrow ?? false;
        $this->errMessage = $errMessage ?? "Error encontrado";
    }
    
    /**
     * Método principal de filtrado
     */
    public function filter($input) {
        $this->errDetails = []; // Limpiar errores anteriores
        
        switch ($this->filterType) {
            case self::inclusive:
                return $this->filterInclusive($input);
            
            case self::exclusive:
                return $this->filterExclusive($input);
            
            case self::all_match:
                return $this->filterAllMatch($input);
            
            case self::strict_exclude:
                return $this->filterStrictExclude($input);
            
            default:
                throw new Exception("Tipo de filtro inválido: {$this->filterType}");
        }
    }
    
    /**
     * Filtro Inclusive (Lista Blanca)
     */
    private function filterInclusive($input) {
        foreach ($this->samples as $key => $sample) {
            if ($this->evaluateSample($sample, $input)) {
                return $input; // Acepta
            }
        }
        
        // Rechaza
        $this->residue[] = $input;
        if ($this->autoThrow) {
            $this->throw();
        }
        return null;
    }
    
    /**
     * Filtro Exclusive (Lista Negra)
     */
    private function filterExclusive($input) {
        foreach ($this->samples as $key => $sample) {
            if ($this->evaluateSample($sample, $input)) {
                // Rechaza
                $this->residue[] = $input;
                if (!is_int($key)) {
                    $this->errDetails[] = $key;
                }
                if ($this->autoThrow) {
                    $this->throw();
                }
                return null;
            }
        }
        
        return $input; // Acepta
    }
    
    /**
     * Filtro All Match (Todas las condiciones deben cumplirse)
     */
    private function filterAllMatch($input) {
        $allPassed = true;
        
        foreach ($this->samples as $key => $sample) {
            if (!$this->evaluateSample($sample, $input)) {
                $allPassed = false;
                if (!is_int($key)) {
                    $this->errDetails[] = $key;
                }
            }
        }
        
        if ($allPassed) {
            return $input; // Acepta
        }
        
        // Rechaza
        $this->residue[] = $input;
        if ($this->autoThrow) {
            $this->throw();
        }
        return null;
    }
    
    /**
     * Filtro Strict Exclude (Rechaza solo si TODAS son true)
     */
    private function filterStrictExclude($input) {
        $allTrue = true;
        
        foreach ($this->samples as $key => $sample) {
            if (!$this->evaluateSample($sample, $input)) {
                $allTrue = false;
                break;
            }
        }
        
        if ($allTrue) {
            // Rechaza (todas las condiciones se cumplieron)
            $this->residue[] = $input;
            if ($this->autoThrow) {
                $this->throw();
            }
            return null;
        }
        
        return $input; // Acepta
    }
    
    /**
     * Evalúa una muestra (puede ser callable o valor directo)
     */
    private function evaluateSample($sample, $input): bool {
        // Si es callable
        if (is_callable($sample)) {
            try {
                return (bool) call_user_func($sample, $input);
            } catch (Exception $e) {
                return false;
            }
        }
        
        // Comparación directa
        return $sample === $input;
    }
    
    /**
     * Lanza excepción con información del error
     */
    public function throw(): void {
        $errorData = [
            'status' => $this->errorType,
            'name' => $this->name,
            'origin' => $this->origin,
            'message' => $this->errMessage,
            'errDetails' => $this->errDetails,
            'residue' => $this->residue
        ];
        
        throw new Exception(json_encode($errorData), $this->errorType);
    }
    
    // ==================== SETTERS ====================
    
    public function setName(string $name): void {
        $this->name = $name;
    }
    
    public function setErrorType(int $type): void {
        $this->errorType = $type;
    }
    
    public function setFilterType(string $type): void {
        if (!in_array($type, [self::inclusive, self::exclusive, self::all_match, self::strict_exclude])) {
            throw new Exception("Tipo de filtro inválido");
        }
        $this->filterType = $type;
    }
    
    public function setOrigin(string $origin): void {
        $this->origin = $origin;
    }
    
    public function setAutoThrow(bool $throw): void {
        $this->autoThrow = $throw;
    }
    
    public function setSamples(array $samples): void {
        $this->samples = $samples;
    }
    
    public function setErrMessage(string $message): void {
        $this->errMessage = $message;
    }
    
    // ==================== GETTERS ====================
    
    public function getName(): string {
        return $this->name;
    }
    
    public function getErrorType(): int {
        return $this->errorType;
    }
    
    public function getFilterType(): string {
        return $this->filterType;
    }
    
    public function getOrigin(): string {
        return $this->origin;
    }
    
    public function getAutoThrow(): bool {
        return $this->autoThrow;
    }
    
    public function getSamples(): array {
        return $this->samples;
    }
    
    public function getErrMessage(): string {
        return $this->errMessage;
    }
    
    public function getErrDetails(): array {
        return $this->errDetails;
    }
    
    public function getResidue(): array {
        return $this->residue;
    }
    
    /**
     * Limpia el historial de errores
     */
    public function clearErrors(): void {
        $this->residue = [];
        $this->errDetails = [];
    }
    
    /**
     * Verifica si hay errores acumulados
     */
    public function hasErrors(): bool {
        return !empty($this->residue) || !empty($this->errDetails);
    }
    
    /**
     * Obtiene un resumen del estado
     */
    public function getStatus(): array {
        return [
            'name' => $this->name,
            'filter_type' => $this->filterType,
            'has_errors' => $this->hasErrors(),
            'error_count' => count($this->residue),
            'details_count' => count($this->errDetails)
        ];
    }
}